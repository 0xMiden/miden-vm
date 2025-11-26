use alloc::{boxed::Box, string::String, sync::Arc, vec::Vec};
use core::fmt;

use miden_core::{
    AdviceMap,
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};
use miden_debug_types::{SourceFile, SourceSpan, Span, Spanned};
use miden_utils_diagnostics::Report;
use smallvec::SmallVec;

use super::{
    Alias, Constant, DocString, EnumType, Export, FunctionType, GlobalItemIndex, ItemIndex,
    LocalSymbolResolutionError, LocalSymbolResolver, Path, Procedure, ProcedureName,
    QualifiedProcedureName, SymbolResolution, TypeAlias, TypeDecl, TypeResolver, Variant,
};
use crate::{
    PathBuf,
    ast::{self, Ident, types},
    parser::ModuleParser,
    sema::SemanticAnalysisError,
};

// MODULE KIND
// ================================================================================================

/// Represents the kind of a [Module].
///
/// The three different kinds have slightly different rules on what syntax is allowed, as well as
/// what operations can be performed in the body of procedures defined in the module. See the
/// documentation for each variant for a summary of these differences.
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum ModuleKind {
    /// A library is a simple container of code that must be included into an executable module to
    /// form a complete program.
    ///
    /// Library modules cannot use the `begin`..`end` syntax, which is used to define the
    /// entrypoint procedure for an executable. Aside from this, they are free to use all other
    /// MASM syntax.
    #[default]
    Library = 0,
    /// An executable is the root module of a program, and provides the entrypoint for executing
    /// that program.
    ///
    /// As the executable module is the root module, it may not export procedures for other modules
    /// to depend on, it may only import and call externally-defined procedures, or private
    /// locally-defined procedures.
    ///
    /// An executable module must contain a `begin`..`end` block.
    Executable = 1,
    /// A kernel is like a library module, but is special in a few ways:
    ///
    /// * Its code always executes in the root context, so it is stateful in a way that normal
    ///   libraries cannot replicate. This can be used to provide core services that would otherwise
    ///   not be possible to implement.
    ///
    /// * The procedures exported from the kernel may be the target of the `syscall` instruction,
    ///   and in fact _must_ be called that way.
    ///
    /// * Kernels may not use `syscall` or `call` instructions internally.
    Kernel = 2,
}

impl ModuleKind {
    pub fn is_executable(&self) -> bool {
        matches!(self, Self::Executable)
    }

    pub fn is_kernel(&self) -> bool {
        matches!(self, Self::Kernel)
    }

    pub fn is_library(&self) -> bool {
        matches!(self, Self::Library)
    }
}

impl fmt::Display for ModuleKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Library => f.write_str("library"),
            Self::Executable => f.write_str("executable"),
            Self::Kernel => f.write_str("kernel"),
        }
    }
}

impl Serializable for ModuleKind {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(*self as u8)
    }
}

impl Deserializable for ModuleKind {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        match source.read_u8()? {
            0 => Ok(Self::Library),
            1 => Ok(Self::Executable),
            2 => Ok(Self::Kernel),
            n => Err(DeserializationError::InvalidValue(format!("invalid module kind tag: {n}"))),
        }
    }
}

// MODULE
// ================================================================================================

/// The abstract syntax tree for a single Miden Assembly module.
///
/// All module kinds share this AST representation, as they are largely identical. However, the
/// [ModuleKind] dictates how the parsed module is semantically analyzed and validated.
#[derive(Clone)]
pub struct Module {
    /// The span covering the entire definition of this module.
    span: SourceSpan,
    /// The documentation associated with this module.
    ///
    /// Module documentation is provided in Miden Assembly as a documentation comment starting on
    /// the first line of the module. All other documentation comments are attached to the item the
    /// precede in the module body.
    docs: Option<DocString>,
    /// The fully-qualified path representing the name of this module.
    path: PathBuf,
    /// The kind of module this represents.
    kind: ModuleKind,
    /// The items (defined or re-exported) in the module body.
    pub(crate) items: Vec<Export>,
    /// AdviceMap that this module expects to be loaded in the host before executing.
    pub(crate) advice_map: AdviceMap,
}

/// Constants
impl Module {
    /// File extension for a Assembly Module.
    pub const FILE_EXTENSION: &'static str = "masm";

    /// Name of the root module.
    pub const ROOT: &'static str = "mod";

    /// File name of the root module.
    pub const ROOT_FILENAME: &'static str = "mod.masm";
}

/// Construction
impl Module {
    /// Creates a new [Module] with the specified `kind` and fully-qualified path, e.g.
    /// `std::math::u64`.
    pub fn new(kind: ModuleKind, path: impl AsRef<Path>) -> Self {
        let path = path.as_ref().to_absolute().into_owned();
        Self {
            span: Default::default(),
            docs: None,
            path,
            kind,
            items: Default::default(),
            advice_map: Default::default(),
        }
    }

    /// An alias for creating the default, but empty, `#kernel` [Module].
    pub fn new_kernel() -> Self {
        Self::new(ModuleKind::Kernel, Path::kernel_path())
    }

    /// An alias for creating the default, but empty, `$exec` [Module].
    pub fn new_executable() -> Self {
        Self::new(ModuleKind::Executable, Path::exec_path())
    }

    /// Specifies the source span in the source file in which this module was defined, that covers
    /// the full definition of this module.
    pub fn with_span(mut self, span: SourceSpan) -> Self {
        self.span = span;
        self
    }

    /// Sets the [Path] for this module
    pub fn set_path(&mut self, path: impl AsRef<Path>) {
        self.path = path.as_ref().to_path_buf();
    }

    /// Modifies the path of this module by overriding the portion of the path preceding
    /// [`Self::name`], i.e. the portion returned by [`Self::parent`].
    ///
    /// See [`PathBuf::set_parent`] for details.
    pub fn set_parent(&mut self, ns: impl AsRef<Path>) {
        self.path.set_parent(ns.as_ref());
    }

    /// Sets the documentation for this module
    pub fn set_docs(&mut self, docs: Option<Span<String>>) {
        self.docs = docs.map(DocString::new);
    }

    /// Like [Module::with_span], but does not require ownership of the [Module].
    pub fn set_span(&mut self, span: SourceSpan) {
        self.span = span;
    }

    /// Defines a constant, raising an error if the constant conflicts with a previous definition
    pub fn define_constant(&mut self, constant: Constant) -> Result<(), SemanticAnalysisError> {
        for item in self.items.iter() {
            if let Export::Constant(c) = item
                && c.name == constant.name
            {
                return Err(SemanticAnalysisError::SymbolConflict {
                    span: constant.span,
                    prev_span: c.span,
                });
            }
        }
        self.items.push(Export::Constant(constant));
        Ok(())
    }

    /// Defines a type alias, raising an error if the alias conflicts with a previous definition
    pub fn define_type(&mut self, ty: TypeAlias) -> Result<(), SemanticAnalysisError> {
        for item in self.items.iter() {
            if let Export::Type(t) = item
                && t.name() == ty.name()
            {
                return Err(SemanticAnalysisError::SymbolConflict {
                    span: ty.span(),
                    prev_span: t.span(),
                });
            }
        }
        self.items.push(Export::Type(ty.into()));
        Ok(())
    }

    /// Define a new enum type `ty` with `visibility`
    ///
    /// Returns `Err` if:
    ///
    /// * A type alias with the same name as the enum type is already defined
    /// * Two or more variants of the given enum type have the same name
    /// * A constant (including those implicitly defined by variants of other enums in this module)
    ///   with the same name as any of the variants of the given enum type, is already defined
    /// * The concrete type of the enumeration is not an integral type
    pub fn define_enum(&mut self, ty: EnumType) -> Result<(), SemanticAnalysisError> {
        let repr = ty.ty().clone();

        if !repr.is_integer() {
            return Err(SemanticAnalysisError::InvalidEnumRepr { span: ty.span() });
        }

        let (alias, variants) = ty.into_parts();

        if let Some(prev) = self.items.iter().find(|t| t.name() == &alias.name) {
            return Err(SemanticAnalysisError::SymbolConflict {
                span: alias.span(),
                prev_span: prev.span(),
            });
        }

        let mut values = SmallVec::<[Span<u64>; 8]>::new_const();

        for variant in variants {
            // Validate that the discriminant value is unique amongst all variants
            let value = match &variant.discriminant {
                ast::ConstantExpr::Int(value) => (*value).map(|v| v.as_int()),
                expr => {
                    return Err(SemanticAnalysisError::InvalidEnumDiscriminant {
                        span: expr.span(),
                        repr,
                    });
                },
            };
            if let Some(prev) = values.iter().find(|v| *v == &value) {
                return Err(SemanticAnalysisError::EnumDiscriminantConflict {
                    span: value.span(),
                    prev: prev.span(),
                });
            } else {
                values.push(value);
            }

            // Validate that the discriminant is a valid instance of the `repr` type
            variant.assert_instance_of(&repr)?;

            let Variant { span, docs, name, discriminant } = variant;

            self.define_constant(Constant {
                span,
                docs,
                visibility: alias.visibility(),
                name,
                value: discriminant,
            })?;
        }

        self.items.push(Export::Type(alias.into()));

        Ok(())
    }

    /// Defines a procedure, raising an error if the procedure is invalid, or conflicts with a
    /// previous definition
    pub fn define_procedure(&mut self, procedure: Procedure) -> Result<(), SemanticAnalysisError> {
        if let Some(prev) = self.resolve(procedure.name().as_ref())? {
            let prev_span = prev.span();
            Err(SemanticAnalysisError::SymbolConflict { span: procedure.span(), prev_span })
        } else {
            self.items.push(Export::Procedure(procedure));
            Ok(())
        }
    }

    /// Defines an item alias, raising an error if the alias is invalid, or conflicts with a
    /// previous definition
    pub fn define_alias(&mut self, item: Alias) -> Result<(), SemanticAnalysisError> {
        if self.is_kernel() && item.visibility().is_public() {
            return Err(SemanticAnalysisError::ReexportFromKernel { span: item.span() });
        }
        if let Some(prev) = self.resolve(item.name())? {
            let prev_span = prev.span();
            Err(SemanticAnalysisError::SymbolConflict { span: item.span(), prev_span })
        } else {
            self.items.push(Export::Alias(item));
            Ok(())
        }
    }
}

/// Parsing
impl Module {
    /// Parse a [Module], `name`, of the given [ModuleKind], from `source_file`.
    pub fn parse(
        name: impl AsRef<Path>,
        kind: ModuleKind,
        source_file: Arc<SourceFile>,
    ) -> Result<Box<Self>, Report> {
        let name = name.as_ref();
        let mut parser = Self::parser(kind);
        parser.parse(name, source_file)
    }

    /// Get a [ModuleParser] for parsing modules of the provided [ModuleKind]
    pub fn parser(kind: ModuleKind) -> ModuleParser {
        ModuleParser::new(kind)
    }
}

/// Metadata
impl Module {
    /// Get the name of this specific module, i.e. the last component of the [Path] that
    /// represents the fully-qualified name of the module, e.g. `u64` in `std::math::u64`
    pub fn name(&self) -> &str {
        self.path.last().expect("non-empty module path")
    }

    /// Get the fully-qualified name of this module, e.g. `std::math::u64`
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Get the path of the parent module of this module, e.g. `std::math` in `std::math::u64`
    pub fn parent(&self) -> Option<&Path> {
        self.path.parent()
    }

    /// Returns true if this module belongs to the provided namespace.
    pub fn is_in_namespace(&self, namespace: &Path) -> bool {
        self.path.starts_with(namespace)
    }

    /// Get the module documentation for this module, if it was present in the source code the
    /// module was parsed from
    pub fn docs(&self) -> Option<Span<&str>> {
        self.docs.as_ref().map(|spanned| spanned.as_spanned_str())
    }

    /// Get the type of module this represents:
    ///
    /// See [ModuleKind] for details on the different types of modules.
    pub fn kind(&self) -> ModuleKind {
        self.kind
    }

    /// Override the type of module this represents.
    ///
    /// See [ModuleKind] for details on what the different types are.
    pub fn set_kind(&mut self, kind: ModuleKind) {
        self.kind = kind;
    }

    /// Returns true if this module is an executable module.
    #[inline(always)]
    pub fn is_executable(&self) -> bool {
        self.kind.is_executable()
    }

    /// Returns true if this module is the top-level kernel module.
    #[inline(always)]
    pub fn is_kernel(&self) -> bool {
        self.kind.is_kernel() && self.path.is_kernel_path()
    }

    /// Returns true if this module is a kernel module.
    #[inline(always)]
    pub fn is_in_kernel(&self) -> bool {
        self.kind.is_kernel()
    }

    /// Returns true if this module has an entrypoint procedure defined,
    /// i.e. a `begin`..`end` block.
    pub fn has_entrypoint(&self) -> bool {
        self.index_of(|p| p.is_main()).is_some()
    }

    /// Returns a reference to the advice map derived from this module
    pub fn advice_map(&self) -> &AdviceMap {
        &self.advice_map
    }

    /// Get an iterator over the constants defined in this module.
    pub fn constants(&self) -> impl Iterator<Item = &Constant> + '_ {
        self.items.iter().filter_map(|item| match item {
            Export::Constant(item) => Some(item),
            _ => None,
        })
    }

    /// Same as [Module::constants], but returns mutable references.
    pub fn constants_mut(&mut self) -> impl Iterator<Item = &mut Constant> + '_ {
        self.items.iter_mut().filter_map(|item| match item {
            Export::Constant(item) => Some(item),
            _ => None,
        })
    }

    /// Get an iterator over the types defined in this module.
    pub fn types(&self) -> impl Iterator<Item = &TypeDecl> + '_ {
        self.items.iter().filter_map(|item| match item {
            Export::Type(item) => Some(item),
            _ => None,
        })
    }

    /// Same as [Module::types], but returns mutable references.
    pub fn types_mut(&mut self) -> impl Iterator<Item = &mut TypeDecl> + '_ {
        self.items.iter_mut().filter_map(|item| match item {
            Export::Type(item) => Some(item),
            _ => None,
        })
    }

    /// Get an iterator over the procedures defined in this module.
    pub fn procedures(&self) -> impl Iterator<Item = &Procedure> + '_ {
        self.items.iter().filter_map(|item| match item {
            Export::Procedure(item) => Some(item),
            _ => None,
        })
    }

    /// Same as [Module::procedures], but returns mutable references.
    pub fn procedures_mut(&mut self) -> impl Iterator<Item = &mut Procedure> + '_ {
        self.items.iter_mut().filter_map(|item| match item {
            Export::Procedure(item) => Some(item),
            _ => None,
        })
    }

    /// Get an iterator over the item aliases in this module.
    pub fn aliases(&self) -> impl Iterator<Item = &Alias> + '_ {
        self.items.iter().filter_map(|item| match item {
            Export::Alias(item) => Some(item),
            _ => None,
        })
    }

    /// Same as [Module::aliases], but returns mutable references.
    pub fn aliases_mut(&mut self) -> impl Iterator<Item = &mut Alias> + '_ {
        self.items.iter_mut().filter_map(|item| match item {
            Export::Alias(item) => Some(item),
            _ => None,
        })
    }

    /// Get an iterator over the items in this module.
    pub fn items(&self) -> core::slice::Iter<'_, Export> {
        self.items.iter()
    }

    /// Same as [Module::items], but returns mutable references.
    pub fn items_mut(&mut self) -> core::slice::IterMut<'_, Export> {
        self.items.iter_mut()
    }

    /// Returns items exported from this module.
    ///
    /// Each exported item is represented by its local item index and a fully qualified name.
    pub fn exported(&self) -> impl Iterator<Item = (ItemIndex, QualifiedProcedureName)> + '_ {
        self.items.iter().enumerate().filter_map(|(idx, item)| {
            // skip un-exported items
            if !item.visibility().is_public() {
                return None;
            }

            let idx = ItemIndex::new(idx);
            let name = ProcedureName::from_raw_parts(item.name().clone());
            let fqn = QualifiedProcedureName::new(self.path.clone(), name);

            Some((idx, fqn))
        })
    }

    /// Gets the type signature for the given [ItemIndex], if available.
    pub fn procedure_signature(&self, id: ItemIndex) -> Option<&FunctionType> {
        self.items[id.as_usize()].signature()
    }

    /// Get the item at `index` in this module's item table.
    ///
    /// The item returned may be either a locally-defined item, or a re-exported item. See [Export]
    /// for details.
    pub fn get(&self, index: ItemIndex) -> Option<&Export> {
        self.items.get(index.as_usize())
    }

    /// Get the [ItemIndex] for the first item in this module's item table which returns true for
    /// `predicate`.
    pub fn index_of<F>(&self, predicate: F) -> Option<ItemIndex>
    where
        F: FnMut(&Export) -> bool,
    {
        self.items.iter().position(predicate).map(ItemIndex::new)
    }

    /// Get the [ItemIndex] for the item whose name is `name` in this module's item table, _if_ that
    /// item is exported.
    ///
    /// Non-exported items can be retrieved by using [Module::index_of].
    pub fn index_of_name(&self, name: &Ident) -> Option<ItemIndex> {
        self.index_of(|item| item.name() == name && item.visibility().is_public())
    }

    /// Resolves `name` to an item within the local scope of this module
    pub fn resolve(
        &self,
        name: &str,
    ) -> Result<Option<SymbolResolution>, ast::LocalSymbolResolutionError> {
        let resolver = self.resolver();
        resolver.resolve(name)
    }

    /// Resolves `path` to an item within the local scope of this module
    pub fn resolve_path(
        &self,
        path: Span<&Path>,
    ) -> Result<Option<SymbolResolution>, ast::LocalSymbolResolutionError> {
        let resolver = self.resolver();
        resolver.resolve_path(path)
    }

    /// Construct a search structure that can resolve procedure names local to this module
    #[inline]
    pub fn resolver(&self) -> LocalSymbolResolver {
        LocalSymbolResolver::from(self)
    }

    /// Resolves `module_name` to an [Alias] within the context of this module
    pub fn get_import(&self, module_name: &str) -> Option<&Alias> {
        self.items.iter().find_map(|item| match item {
            Export::Alias(item) if item.name().as_str() == module_name => Some(item),
            _ => None,
        })
    }

    /// Same as [Module::get_import], but returns a mutable reference to the [Alias]
    pub fn get_import_mut(&mut self, module_name: &str) -> Option<&mut Alias> {
        self.items.iter_mut().find_map(|item| match item {
            Export::Alias(item) if item.name().as_str() == module_name => Some(item),
            _ => None,
        })
    }

    /// Resolves a user-expressed type, `ty`, to a concrete type
    pub fn resolve_type(
        &self,
        ty: &ast::TypeExpr,
    ) -> Result<Option<types::Type>, LocalSymbolResolutionError> {
        let type_resolver = ModuleTypeResolver::new(self);
        type_resolver.resolve(ty)
    }

    /// Get a type resolver for this module
    pub fn type_resolver(&self) -> impl TypeResolver<LocalSymbolResolutionError> + '_ {
        ModuleTypeResolver::new(self)
    }
}

impl core::ops::Index<ItemIndex> for Module {
    type Output = Export;

    #[inline]
    fn index(&self, index: ItemIndex) -> &Self::Output {
        &self.items[index.as_usize()]
    }
}

impl core::ops::IndexMut<ItemIndex> for Module {
    #[inline]
    fn index_mut(&mut self, index: ItemIndex) -> &mut Self::Output {
        &mut self.items[index.as_usize()]
    }
}

impl Spanned for Module {
    fn span(&self) -> SourceSpan {
        self.span
    }
}

impl Eq for Module {}

impl PartialEq for Module {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.path == other.path
            && self.docs == other.docs
            && self.items == other.items
    }
}

/// Debug representation of this module
impl fmt::Debug for Module {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Module")
            .field("docs", &self.docs)
            .field("path", &self.path)
            .field("kind", &self.kind)
            .field("items", &self.items)
            .finish()
    }
}

/// Pretty-printed representation of this module as Miden Assembly text format
///
/// NOTE: Delegates to the [crate::prettier::PrettyPrint] implementation internally
impl fmt::Display for Module {
    /// Writes this [Module] as formatted MASM code into the formatter.
    ///
    /// The formatted code puts each instruction on a separate line and preserves correct
    /// indentation for instruction blocks.
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use crate::prettier::PrettyPrint;

        self.pretty_print(f)
    }
}

/// The pretty-printer for [Module]
impl crate::prettier::PrettyPrint for Module {
    fn render(&self) -> crate::prettier::Document {
        use crate::prettier::*;

        let mut doc = self
            .docs
            .as_ref()
            .map(|docstring| docstring.render() + nl())
            .unwrap_or(Document::Empty);

        let mut item_index = 0;
        for item in self.items.iter() {
            if item.is_main() {
                continue;
            }

            if item_index > 0 {
                doc += nl();
            }
            doc += item.render();
            item_index += 1;
        }

        if let Some(main) = self.items.iter().find(|item| item.is_main()) {
            if item_index > 0 {
                doc += nl();
            }
            doc += main.render();
        }

        doc
    }
}

struct ModuleTypeResolver<'a> {
    module: &'a Module,
    resolver: LocalSymbolResolver,
}

impl<'a> ModuleTypeResolver<'a> {
    pub fn new(module: &'a Module) -> Self {
        let resolver = module.resolver();
        Self { module, resolver }
    }
}

impl TypeResolver<LocalSymbolResolutionError> for ModuleTypeResolver<'_> {
    fn get_type(
        &self,
        context: SourceSpan,
        _gid: GlobalItemIndex,
    ) -> Result<ast::types::Type, LocalSymbolResolutionError> {
        Err(LocalSymbolResolutionError::UndefinedSymbol { span: context })
    }
    fn get_local_type(
        &self,
        context: SourceSpan,
        id: ItemIndex,
    ) -> Result<Option<ast::types::Type>, LocalSymbolResolutionError> {
        match &self.module[id] {
            super::Export::Type(ty) => match ty {
                TypeDecl::Alias(ty) => self.resolve(&ty.ty),
                TypeDecl::Enum(ty) => Ok(Some(ty.ty().clone())),
            },
            item => Err(self.resolve_local_failed(LocalSymbolResolutionError::InvalidSymbolType {
                expected: "type",
                span: context,
                actual: item.span(),
            })),
        }
    }
    #[inline(always)]
    fn resolve_local_failed(&self, err: LocalSymbolResolutionError) -> LocalSymbolResolutionError {
        err
    }
    fn resolve_type_ref(
        &self,
        path: Span<&Path>,
    ) -> Result<Option<SymbolResolution>, LocalSymbolResolutionError> {
        self.resolver.resolve_path(path)
    }
}
