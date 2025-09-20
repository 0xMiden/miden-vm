use core::fmt;

use miden_debug_types::{SourceSpan, Spanned};

use crate::{LibraryNamespace, LibraryPath, ast::Ident};

// IMPORT
// ================================================================================================

/// Represents an import statement in Miden Assembly syntax.
#[derive(Clone)]
pub struct Import {
    /// The source span of the statement.
    pub span: SourceSpan,
    /// The local module name/alias.
    ///
    /// When the imported item is aliased to a new name, this field contains the alias, while
    /// `path.last()` can be used to obtain the actual name.
    pub name: Ident,
    /// The fully-qualified path.
    pub path: LibraryPath,
    /// The number of times this import has been used locally.
    pub uses: usize,
}

impl Import {
    /// Returns true if this import is aliased to a different name in its containing module.
    pub fn is_aliased(&self) -> bool {
        self.name.as_ref() != self.path.last()
    }

    /// Returns the namespace of the imported module.
    pub fn namespace(&self) -> &LibraryNamespace {
        self.path.namespace()
    }

    /// Returns the fully-qualified path of the imported module.
    pub fn path(&self) -> &LibraryPath {
        &self.path
    }

    /// Returns true if this import has at least one use in its containing module.
    pub fn is_used(&self) -> bool {
        self.uses > 0
    }
}

impl fmt::Debug for Import {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Import")
            .field("name", &self.name)
            .field("path", &self.path)
            .field("uses", &self.uses)
            .finish()
    }
}

impl crate::prettier::PrettyPrint for Import {
    fn render(&self) -> crate::prettier::Document {
        use crate::prettier::*;

        let mut doc = const_text("use") + const_text(" ") + display(&self.path);
        if self.is_aliased() {
            doc += const_text("->") + display(&self.name);
        }
        doc
    }
}

impl Eq for Import {}

impl PartialEq for Import {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.path == other.path
    }
}

impl Spanned for Import {
    fn span(&self) -> SourceSpan {
        self.span
    }
}
