use alloc::{string::String, sync::Arc};
use core::fmt;

use miden_debug_types::{SourceSpan, Span, Spanned};

use crate::{
    Path, Word,
    ast::{DocString, Ident, InvocationTarget, Visibility},
};

// ITEM ALIAS
// ================================================================================================

/// Represents an item that acts like it is locally-defined, but is actually externally-defined.
///
/// These "aliases" do not have a concrete representation in the module, but are instead resolved
/// during compilation to refer directly to the aliased item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alias {
    /// The documentation attached to this item
    docs: Option<DocString>,
    /// The visibility of this item
    visibility: Visibility,
    /// The name of this item
    name: Ident,
    /// The underlying item being aliased.
    ///
    /// Alias targets are context-sensitive, depending on how they were defined and what stage of
    /// compilation we're in. See [AliasTarget] for semantics of each target type, but they closely
    /// correspond to [InvocationTarget].
    ///
    /// NOTE: `AliasTarget::MastRoot` is _only_ a valid target for procedure items
    target: AliasTarget,
    /// The number of times this import has been used locally.
    pub uses: usize,
}

impl Alias {
    /// Creates a new item alias called `name`, which resolves to `target`.
    pub fn new(visibility: Visibility, name: Ident, target: AliasTarget) -> Self {
        Self {
            docs: None,
            visibility,
            name,
            target,
            uses: 0,
        }
    }

    /// Adds documentation to this alias.
    pub fn with_docs(mut self, docs: Option<Span<String>>) -> Self {
        self.docs = docs.map(DocString::new);
        self
    }

    /// Returns the documentation associated with this item.
    pub fn docs(&self) -> Option<Span<&str>> {
        self.docs.as_ref().map(|docstring| docstring.as_spanned_str())
    }

    /// Returns the visibility of this alias
    #[inline]
    pub const fn visibility(&self) -> Visibility {
        self.visibility
    }

    /// Returns the name of this alias within its containing module.
    ///
    /// If the item is simply re-exported with the same name, this will be equivalent to
    /// `self.target().name`
    #[inline]
    pub fn name(&self) -> &Ident {
        &self.name
    }

    /// Returns the target of this alias
    #[inline]
    pub fn target(&self) -> &AliasTarget {
        &self.target
    }

    /// Returns a mutable reference to the target of this alias
    #[inline]
    pub fn target_mut(&mut self) -> &mut AliasTarget {
        &mut self.target
    }

    /// Returns true if this alias uses an absolute target path
    #[inline]
    pub fn is_absolute(&self) -> bool {
        match self.target() {
            AliasTarget::MastRoot(_) => true,
            AliasTarget::Path(path) => path.is_absolute(),
        }
    }

    /// Returns true if this alias uses a different name than the target
    #[inline]
    pub fn is_renamed(&self) -> bool {
        match self.target() {
            AliasTarget::MastRoot(_) => true,
            AliasTarget::Path(path) => path.last().unwrap() != self.name.as_str(),
        }
    }

    /// Returns true if this import has at least one use in its containing module.
    pub fn is_used(&self) -> bool {
        self.uses > 0 || self.visibility.is_public()
    }
}

impl Spanned for Alias {
    fn span(&self) -> SourceSpan {
        self.target.span()
    }
}

impl crate::prettier::PrettyPrint for Alias {
    fn render(&self) -> crate::prettier::Document {
        use crate::prettier::*;

        let mut doc = self
            .docs
            .as_ref()
            .map(|docstring| docstring.render())
            .unwrap_or(Document::Empty);

        if self.visibility.is_public() {
            doc += display(self.visibility) + const_text(" ");
        }
        doc += const_text("use ");
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

/// A fully-qualified external item that is the target of an alias
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AliasTarget {
    /// An alias of the procedure whose root is the given digest
    ///
    /// This target type is only valid for procedures.
    ///
    /// Corresponds to [`InvocationTarget::MastRoot`]
    MastRoot(Span<Word>),
    /// An alias of an item using a path that may need to be resolved relative to the importing
    /// module.
    ///
    /// Corresponds to [`InvocationTarget::Path`]
    Path(Span<Arc<Path>>),
}

impl AliasTarget {
    pub fn unwrap_path(&self) -> &Arc<Path> {
        match self {
            Self::Path(path) => path.inner(),
            Self::MastRoot(_) => {
                panic!("expected alias target to be a path, but got a mast digest")
            },
        }
    }
}

impl Spanned for AliasTarget {
    fn span(&self) -> SourceSpan {
        match self {
            Self::MastRoot(spanned) => spanned.span(),
            Self::Path(spanned) => spanned.span(),
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
        match target {
            InvocationTarget::MastRoot(digest) => Ok(Self::MastRoot(digest)),
            InvocationTarget::Path(path) => Ok(Self::Path(path)),
            target @ InvocationTarget::Symbol(_) => Err(target),
        }
    }
}

impl From<&AliasTarget> for InvocationTarget {
    fn from(target: &AliasTarget) -> Self {
        match target {
            AliasTarget::MastRoot(digest) => Self::MastRoot(*digest),
            AliasTarget::Path(path) => Self::Path(path.clone()),
        }
    }
}
impl From<AliasTarget> for InvocationTarget {
    fn from(target: AliasTarget) -> Self {
        match target {
            AliasTarget::MastRoot(digest) => Self::MastRoot(digest),
            AliasTarget::Path(path) => Self::Path(path),
        }
    }
}

impl crate::prettier::PrettyPrint for AliasTarget {
    fn render(&self) -> crate::prettier::Document {
        use miden_core::utils::DisplayHex;

        use crate::prettier::*;

        match self {
            Self::MastRoot(digest) => display(DisplayHex(digest.as_bytes().as_slice())),
            Self::Path(path) => display(path),
        }
    }
}

impl fmt::Display for AliasTarget {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use crate::prettier::PrettyPrint;

        self.pretty_print(f)
    }
}
