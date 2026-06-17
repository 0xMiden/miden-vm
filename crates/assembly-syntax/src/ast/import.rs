use alloc::{sync::Arc, vec::Vec};

use miden_debug_types::{SourceSpan, Span, Spanned};

use super::{Ident, Path, Visibility};

/// The explicit source form used by an import declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportKind {
    /// A module import such as `use some::module` or `use some::module as sm`.
    Module,
    /// An item import such as `use {foo, bar as baz} from some::module`.
    Item,
}

/// A source-level import declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportDecl {
    Module(ModuleImport),
    Items(ItemImportGroup),
}

/// A concrete import recorded in a semantically-analyzed module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Import {
    Module(ModuleImport),
    Item(ItemImport),
}

/// Imports a foreign module into scope under a local name.
#[derive(Debug, Clone)]
pub struct ModuleImport {
    span: SourceSpan,
    visibility: Visibility,
    module_path: Span<Arc<Path>>,
    local_name: Ident,
    /// The number of times this import has been used locally.
    pub uses: usize,
}

/// Imports one or more foreign items from a module.
#[derive(Debug, Clone)]
pub struct ItemImportGroup {
    span: SourceSpan,
    visibility: Visibility,
    module_path: Span<Arc<Path>>,
    specs: Vec<ImportSpec>,
}

/// A single item import within an item import group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportSpec {
    source_name: Ident,
    local_name: Ident,
}

/// Imports a single foreign item from a module into the local scope.
#[derive(Debug, Clone)]
pub struct ItemImport {
    span: SourceSpan,
    visibility: Visibility,
    module_path: Span<Arc<Path>>,
    source_name: Ident,
    local_name: Ident,
    /// The number of times this import has been used locally.
    pub uses: usize,
}

impl ImportDecl {
    pub fn kind(&self) -> ImportKind {
        match self {
            Self::Module(_) => ImportKind::Module,
            Self::Items(_) => ImportKind::Item,
        }
    }

    pub fn visibility(&self) -> Visibility {
        match self {
            Self::Module(import) => import.visibility(),
            Self::Items(import) => import.visibility(),
        }
    }

    pub fn module_path(&self) -> Span<&Path> {
        match self {
            Self::Module(import) => import.module_path(),
            Self::Items(import) => import.module_path(),
        }
    }
}

impl Import {
    pub fn kind(&self) -> ImportKind {
        match self {
            Self::Module(_) => ImportKind::Module,
            Self::Item(_) => ImportKind::Item,
        }
    }

    pub fn visibility(&self) -> Visibility {
        match self {
            Self::Module(import) => import.visibility(),
            Self::Item(import) => import.visibility(),
        }
    }

    pub fn module_path(&self) -> Span<&Path> {
        match self {
            Self::Module(import) => import.module_path(),
            Self::Item(import) => import.module_path(),
        }
    }

    pub fn local_name(&self) -> &Ident {
        match self {
            Self::Module(import) => import.local_name(),
            Self::Item(import) => import.local_name(),
        }
    }

    /// Returns true if this import has at least one use in its containing module.
    pub fn is_used(&self) -> bool {
        match self {
            Self::Module(import) => import.is_used(),
            Self::Item(import) => import.is_used(),
        }
    }

    /// Returns the most specific source span for unused-import diagnostics.
    pub fn unused_span(&self) -> SourceSpan {
        match self {
            Self::Module(import) => import.local_name().span(),
            Self::Item(import) => import.local_name().span(),
        }
    }
}

impl ModuleImport {
    pub fn new(
        span: SourceSpan,
        visibility: Visibility,
        module_path: Span<Arc<Path>>,
        local_name: Ident,
    ) -> Self {
        Self {
            span,
            visibility,
            module_path,
            local_name,
            uses: 0,
        }
    }

    pub fn visibility(&self) -> Visibility {
        self.visibility
    }

    pub fn module_path(&self) -> Span<&Path> {
        self.module_path.as_deref()
    }

    pub fn set_module_path(&mut self, path: Span<Arc<Path>>) {
        self.module_path = path;
    }

    pub fn local_name(&self) -> &Ident {
        &self.local_name
    }

    /// Returns true if this import has at least one use in its containing module.
    pub fn is_used(&self) -> bool {
        self.uses > 0
    }
}

impl ItemImportGroup {
    pub fn new(
        span: SourceSpan,
        visibility: Visibility,
        module_path: Span<Arc<Path>>,
        specs: Vec<ImportSpec>,
    ) -> Self {
        Self { span, visibility, module_path, specs }
    }

    pub fn visibility(&self) -> Visibility {
        self.visibility
    }

    pub fn module_path(&self) -> Span<&Path> {
        self.module_path.as_deref()
    }

    pub fn specs(&self) -> &[ImportSpec] {
        &self.specs
    }
}

impl ImportSpec {
    pub fn new(source_name: Ident, local_name: Ident) -> Self {
        Self { source_name, local_name }
    }

    pub fn source_name(&self) -> &Ident {
        &self.source_name
    }

    pub fn local_name(&self) -> &Ident {
        &self.local_name
    }

    pub fn is_renamed(&self) -> bool {
        self.source_name != self.local_name
    }
}

impl ItemImport {
    pub fn new(
        span: SourceSpan,
        visibility: Visibility,
        module_path: Span<Arc<Path>>,
        source_name: Ident,
        local_name: Ident,
    ) -> Self {
        Self {
            span,
            visibility,
            module_path,
            source_name,
            local_name,
            uses: 0,
        }
    }

    pub fn visibility(&self) -> Visibility {
        self.visibility
    }

    pub fn module_path(&self) -> Span<&Path> {
        self.module_path.as_deref()
    }

    pub fn source_name(&self) -> &Ident {
        &self.source_name
    }

    pub fn local_name(&self) -> &Ident {
        &self.local_name
    }

    pub fn target_path(&self) -> Span<Arc<Path>> {
        Span::new(self.source_name.span(), self.module_path.inner().join(&self.source_name).into())
    }

    /// Returns true if this import has at least one use in its containing module.
    pub fn is_used(&self) -> bool {
        self.uses > 0 || self.visibility.is_public()
    }
}

impl Spanned for Import {
    fn span(&self) -> SourceSpan {
        match self {
            Self::Module(import) => import.span(),
            Self::Item(import) => import.span(),
        }
    }
}

impl Spanned for ImportDecl {
    fn span(&self) -> SourceSpan {
        match self {
            Self::Module(import) => import.span(),
            Self::Items(import) => import.span(),
        }
    }
}

impl Spanned for ModuleImport {
    fn span(&self) -> SourceSpan {
        self.span
    }
}

impl Spanned for ItemImportGroup {
    fn span(&self) -> SourceSpan {
        self.span
    }
}

impl Spanned for ImportSpec {
    fn span(&self) -> SourceSpan {
        self.source_name.span()
    }
}

impl Spanned for ItemImport {
    fn span(&self) -> SourceSpan {
        self.span
    }
}

impl Eq for ModuleImport {}

impl PartialEq for ModuleImport {
    fn eq(&self, other: &Self) -> bool {
        self.visibility == other.visibility
            && self.module_path.inner() == other.module_path.inner()
            && self.local_name == other.local_name
    }
}

impl Eq for ItemImportGroup {}

impl PartialEq for ItemImportGroup {
    fn eq(&self, other: &Self) -> bool {
        self.visibility == other.visibility
            && self.module_path.inner() == other.module_path.inner()
            && self.specs == other.specs
    }
}

impl Eq for ItemImport {}

impl PartialEq for ItemImport {
    fn eq(&self, other: &Self) -> bool {
        self.visibility == other.visibility
            && self.module_path.inner() == other.module_path.inner()
            && self.source_name == other.source_name
            && self.local_name == other.local_name
    }
}

impl crate::prettier::PrettyPrint for ImportDecl {
    fn render(&self) -> crate::prettier::Document {
        match self {
            Self::Module(import) => import.render(),
            Self::Items(import) => import.render(),
        }
    }
}

impl crate::prettier::PrettyPrint for Import {
    fn render(&self) -> crate::prettier::Document {
        match self {
            Self::Module(import) => import.render(),
            Self::Item(import) => import.render(),
        }
    }
}

impl crate::prettier::PrettyPrint for ModuleImport {
    fn render(&self) -> crate::prettier::Document {
        use crate::prettier::*;

        let mut doc = const_text("use") + const_text(" ") + display(self.module_path.inner());
        if self.module_path.last().is_none_or(|name| name != self.local_name.as_str()) {
            doc += const_text(" as ") + display(&self.local_name);
        }
        doc
    }
}

impl crate::prettier::PrettyPrint for ItemImportGroup {
    fn render(&self) -> crate::prettier::Document {
        use crate::prettier::*;

        let mut doc = Document::Empty;
        if self.visibility.is_public() {
            doc += display(self.visibility) + const_text(" ");
        }
        doc += const_text("use {");

        for (index, spec) in self.specs.iter().enumerate() {
            if index > 0 {
                doc += const_text(", ");
            }
            doc += spec.render();
        }

        doc + const_text("} from ") + display(self.module_path.inner())
    }
}

impl crate::prettier::PrettyPrint for ImportSpec {
    fn render(&self) -> crate::prettier::Document {
        use crate::prettier::*;

        let mut doc = display(&self.source_name);
        if self.is_renamed() {
            doc += const_text(" as ") + display(&self.local_name);
        }
        doc
    }
}

impl crate::prettier::PrettyPrint for ItemImport {
    fn render(&self) -> crate::prettier::Document {
        use crate::prettier::*;

        let mut doc = Document::Empty;
        if self.visibility.is_public() {
            doc += display(self.visibility) + const_text(" ");
        }
        doc += const_text("use {") + display(&self.source_name);
        if self.source_name != self.local_name {
            doc += const_text(" as ") + display(&self.local_name);
        }
        doc + const_text("} from ") + display(self.module_path.inner())
    }
}
