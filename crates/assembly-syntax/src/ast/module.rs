use alloc::{
    boxed::Box,
    collections::BTreeMap,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::fmt;

use miden_core::{
    advice::AdviceMap,
    serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};
use miden_debug_types::{SourceFile, SourceManager, SourceSpan, Span, Spanned};
use miden_utils_diagnostics::Report;
#[cfg(feature = "arbitrary")]
use proptest::prelude::*;
use smallvec::SmallVec;

use super::{
    Constant, Declaration, DocString, EnumType, FunctionType, Import, Item, ItemIndex, Path,
    Procedure, ProcedureName, QualifiedProcedureName, SubmoduleDecl, TypeAlias, TypeDecl, Variant,
    Visibility,
};
use crate::{
    PathBuf,
    ast::{self, Ident},
    parser::ModuleParser,
    sema::{LimitKind, SemanticAnalysisError},
};

// MODULE KIND
// ================================================================================================

/// Represents the kind of a [Module].
///
/// The three different kinds have slightly different rules on what syntax is allowed, as well as
/// what operations can be performed in the body of procedures defined in the module. See the
/// documentation for each variant for a summary of these differences.
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true), serde_test(false))
)]
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

#[cfg(feature = "arbitrary")]
impl Arbitrary for ModuleKind {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        any::<u8>()
            .prop_map(|tag| match tag % 3 {
                0 => Self::Library,
                1 => Self::Executable,
                _ => Self::Kernel,
            })
            .boxed()
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
    /// The namespace given by a `namespace` declaration, if present in this module
    ///
    /// The `namespace` declaration is optional when the module being parsed is part of a project
    /// controlled by a `miden-project.toml` manifest. If present at the same time as a controlling
    /// manifest, the namespace must agree with what is specified in `miden-project.toml`.
    ///
    /// The `namespace` declaration is only permitted in the root module of a project - if present
    /// in any submodules, an error will be raised.
    pub(crate) namespace_decl: Option<Span<Arc<Path>>>,
    /// The set of external package requirements declared in this module.
    ///
    /// The `extern package "<package-id>"` declaration is optional when either the module being
    /// parsed is part of a project controlled by a `miden-project.toml` manifest; or when the
    /// module and its submodules has no external dependencies. If present at the same time as a
    /// controlling manifest, the set of `extern package` declarations must agree exactly with what
    /// is specified in `miden-project.toml`.
    ///
    /// The `extern package` declaration is only permitted in the root module of a project - if
    /// present in any submodules, an error will be raised.
    pub(crate) extern_packages: Vec<Ident>,
    /// The set of submodule declarations in this module, i.e. `mod foo` or `pub mod foo`
    ///
    /// If specified, it is expected that a module with the given
    pub(crate) submodules: Vec<SubmoduleDecl>,
    /// The imports declared by this module.
    pub(crate) imports: Vec<Import>,
    /// The items (defined or re-exported) in the module body.
    pub(crate) items: Vec<Item>,
    /// Maps export name to its position in `items`, for O(log n) conflict checks.
    /// Must be kept in sync with `items` via `push_export`.
    name_map: BTreeMap<String, usize>,
    /// Whether mutable item access may have changed item names without updating `name_map`.
    name_map_dirty: bool,
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
        let path = path.as_ref().to_absolute().unwrap().into_owned();
        Self {
            span: Default::default(),
            docs: None,
            path,
            kind,
            namespace_decl: None,
            extern_packages: Default::default(),
            submodules: Default::default(),
            imports: Default::default(),
            items: Default::default(),
            name_map: BTreeMap::new(),
            name_map_dirty: false,
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

    /// Registers that `namespace` was explicitly declared for this module via `namespace <ns>`
    ///
    /// This will also override the module path to ensure they agree
    pub(crate) fn set_declared_namespace(&mut self, namespace: Span<Arc<Path>>) {
        self.path = namespace.to_path_buf();
        self.namespace_decl = Some(namespace);
    }

    fn ensure_item_capacity(&self, span: SourceSpan) -> Result<(), SemanticAnalysisError> {
        if self.items.len() >= ItemIndex::MAX_ITEMS {
            return Err(SemanticAnalysisError::LimitExceeded { span, kind: LimitKind::Items });
        }

        Ok(())
    }

    pub(crate) fn push_export(&mut self, item: Item) -> Result<(), SemanticAnalysisError> {
        self.ensure_item_capacity(item.span())?;
        self.ensure_name_map_current();
        let idx = self.items.len();
        let prev = self.name_map.insert(item.name().to_string(), idx);
        debug_assert!(prev.is_none(), "duplicate export inserted via push_export: {}", item.name());
        self.items.push(item);
        Ok(())
    }

    fn ensure_name_map_current(&mut self) {
        if !self.name_map_dirty {
            return;
        }

        self.name_map.clear();
        self.name_map.extend(
            self.items.iter().enumerate().map(|(idx, item)| (item.name().to_string(), idx)),
        );
        self.name_map_dirty = false;
    }

    /// Takes all items from this module, clearing the name index.
    /// Used by the linker to consume module contents.
    pub fn take_items(&mut self) -> Vec<Item> {
        self.name_map.clear();
        self.name_map_dirty = false;
        core::mem::take(&mut self.items)
    }

    /// Get the [Declaration] corresponding to `name` in this module, if `name` has been declared
    pub(crate) fn get_declaration<'module>(
        &'module self,
        name: &str,
    ) -> Option<Declaration<'module>> {
        self.get_item(name)
            .map(Declaration::Item)
            .or_else(|| self.get_import(name).map(Declaration::Import))
            .or_else(|| self.get_submodule_declaration(name).map(Declaration::Submodule))
    }

    #[inline]
    pub(crate) fn get_item(&self, name: &str) -> Option<&Item> {
        self.name_map.get(name).copied().map(|idx| &self.items[idx])
    }

    #[inline]
    pub(crate) fn get_submodule_declaration(&self, name: &str) -> Option<&SubmoduleDecl> {
        self.submodules.iter().find(|decl| decl.name.as_str() == name)
    }

    fn ensure_import_capacity(&self, span: SourceSpan) -> Result<(), SemanticAnalysisError> {
        if self.imports.len() + self.items.len() >= ItemIndex::MAX_ITEMS {
            return Err(SemanticAnalysisError::LimitExceeded { span, kind: LimitKind::Imports });
        }

        Ok(())
    }

    /// Declares that this module has a submodule named `name`, with the specified `visibility`.
    ///
    /// This returns an error if it conflicts with a previous declaration (either a previous
    /// submodule declaration, or an imported symbol name).
    pub fn declare_submodule(
        &mut self,
        name: Ident,
        visibility: Visibility,
    ) -> Result<(), SemanticAnalysisError> {
        if let Some(decl) = self.get_declaration(name.as_str()) {
            return Err(SemanticAnalysisError::SymbolConflict {
                span: name.span(),
                prev_span: decl.span(),
            });
        }
        self.submodules.push(SubmoduleDecl { visibility, name });
        Ok(())
    }

    /// Declares that this module has a dependency on the library target of an external package
    /// named `name`.
    ///
    /// This returns an error if it conflicts with a previous `extern package` declaration.
    pub fn declare_extern_package(&mut self, name: Ident) -> Result<(), SemanticAnalysisError> {
        if let Some(prev) = self.extern_packages.iter().find(|ep| *ep == &name) {
            return Err(SemanticAnalysisError::ExternPackageConflict {
                span: name.span(),
                prev_span: prev.span(),
            });
        }
        self.extern_packages.push(name);
        Ok(())
    }

    /// Defines a constant, raising an error if the constant conflicts with a previous definition
    pub fn define_constant(&mut self, constant: Constant) -> Result<(), SemanticAnalysisError> {
        self.ensure_name_map_current();
        if let Some(prev) = self.get_declaration(constant.name.as_str()) {
            return Err(SemanticAnalysisError::SymbolConflict {
                span: constant.span,
                prev_span: prev.span(),
            });
        }
        self.push_export(Item::Constant(constant))
    }

    /// Defines a type alias, raising an error if the alias conflicts with a previous definition
    pub fn define_type(&mut self, ty: TypeAlias) -> Result<(), SemanticAnalysisError> {
        self.ensure_name_map_current();
        if let Some(prev) = self.get_declaration(ty.name.as_str()) {
            return Err(SemanticAnalysisError::SymbolConflict {
                span: ty.span(),
                prev_span: prev.span(),
            });
        }
        self.push_export(Item::Type(ty.into()))
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
        self.ensure_name_map_current();
        let repr = ty.ty().clone();
        let is_c_like = ty.is_c_like();

        if !repr.is_integer() {
            return Err(SemanticAnalysisError::InvalidEnumRepr { span: ty.span() });
        }

        let export = ty.clone();
        let (alias, variants) = ty.into_parts();

        if let Some(prev) = self.get_declaration(alias.name().as_str()) {
            return Err(SemanticAnalysisError::SymbolConflict {
                span: alias.span(),
                prev_span: prev.span(),
            });
        }

        // We only define constants for C-like enums
        if !is_c_like {
            self.push_export(Item::Type(export.into()))?;
            return Ok(());
        }
        // Check that no variant name conflicts with the enum type name itself
        if let Some(conflict) = variants.iter().find(|v| v.name.as_str() == alias.name.as_str()) {
            return Err(SemanticAnalysisError::SymbolConflict {
                span: conflict.name.span(),
                prev_span: alias.span(),
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

            let Variant {
                span,
                docs,
                name,
                value_ty: _,
                discriminant,
            } = variant;

            self.define_constant(Constant {
                span,
                docs,
                visibility: alias.visibility(),
                name,
                value: discriminant,
            })?;
        }

        self.push_export(Item::Type(export.into()))?;

        Ok(())
    }

    /// Defines a procedure, raising an error if the procedure is invalid, or conflicts with a
    /// previous definition
    pub fn define_procedure(
        &mut self,
        procedure: Procedure,
        _source_manager: Arc<dyn SourceManager>,
    ) -> Result<(), SemanticAnalysisError> {
        self.ensure_name_map_current();
        if let Some(prev) = self.get_declaration(procedure.name().as_str()) {
            return Err(SemanticAnalysisError::SymbolConflict {
                span: procedure.span(),
                prev_span: prev.span(),
            });
        }
        self.push_export(Item::Procedure(procedure))
    }

    /// Defines an import, raising an error if the import conflicts with a previous declaration.
    pub fn define_import(&mut self, import: Import) -> Result<(), SemanticAnalysisError> {
        self.ensure_name_map_current();
        self.ensure_import_capacity(import.span())?;
        if self.is_kernel() && import.visibility().is_public() {
            return Err(SemanticAnalysisError::ReexportFromKernel { span: import.span() });
        }
        if let Some(prev) = self.get_declaration(import.local_name().as_str()) {
            return Err(SemanticAnalysisError::SymbolConflict {
                span: import.local_name().span(),
                prev_span: prev.span(),
            });
        }
        self.imports.push(import);
        Ok(())
    }
}

/// Parsing
impl Module {
    /// Parse a [Module], `name`, of the given [ModuleKind], from `source_file`.
    pub fn parse(
        name: impl AsRef<Path>,
        source_file: Arc<SourceFile>,
        source_manager: Arc<dyn SourceManager>,
    ) -> Result<Box<Self>, Report> {
        let name = name.as_ref();
        let kind = if name.is_kernel_path() {
            Some(ModuleKind::Kernel)
        } else {
            None
        };
        let mut parser = Self::parser(kind);
        parser.parse(Some(name), source_file, source_manager)
    }

    pub fn parse_kernel(
        source_file: Arc<SourceFile>,
        source_manager: Arc<dyn SourceManager>,
    ) -> Result<Box<Self>, Report> {
        let mut parser = Self::parser(Some(ModuleKind::Kernel));
        parser.parse(Some(Path::KERNEL), source_file, source_manager)
    }

    /// Get a [ModuleParser] for parsing modules of the provided [ModuleKind]
    ///
    /// If `kind` is `None`, then the module kind is inferred as either library or executable based
    /// on whether the module contains a `begin` block. If you wish to parse a kernel module, it
    /// must be done explicitly.
    pub fn parser(kind: Option<ModuleKind>) -> ModuleParser {
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
        self.index_of(Item::is_main).is_some()
    }

    /// Returns a reference to the advice map derived from this module
    pub fn advice_map(&self) -> &AdviceMap {
        &self.advice_map
    }

    /// Get an iterator over the constants defined in this module.
    pub fn constants(&self) -> impl Iterator<Item = &Constant> + '_ {
        self.items.iter().filter_map(|item| match item {
            Item::Constant(item) => Some(item),
            _ => None,
        })
    }

    /// Same as [Module::constants], but returns mutable references.
    pub fn constants_mut(&mut self) -> impl Iterator<Item = &mut Constant> + '_ {
        self.name_map_dirty = true;
        self.items.iter_mut().filter_map(|item| match item {
            Item::Constant(item) => Some(item),
            _ => None,
        })
    }

    /// Get an iterator over the types defined in this module.
    pub fn types(&self) -> impl Iterator<Item = &TypeDecl> + '_ {
        self.items.iter().filter_map(|item| match item {
            Item::Type(item) => Some(item),
            _ => None,
        })
    }

    /// Same as [Module::types], but returns mutable references.
    pub fn types_mut(&mut self) -> impl Iterator<Item = &mut TypeDecl> + '_ {
        self.name_map_dirty = true;
        self.items.iter_mut().filter_map(|item| match item {
            Item::Type(item) => Some(item),
            _ => None,
        })
    }

    /// Get an iterator over the procedures defined in this module.
    pub fn procedures(&self) -> impl Iterator<Item = &Procedure> + '_ {
        self.items.iter().filter_map(|item| match item {
            Item::Procedure(item) => Some(item),
            _ => None,
        })
    }

    /// Same as [Module::procedures], but returns mutable references.
    pub fn procedures_mut(&mut self) -> impl Iterator<Item = &mut Procedure> + '_ {
        self.name_map_dirty = true;
        self.items.iter_mut().filter_map(|item| match item {
            Item::Procedure(item) => Some(item),
            _ => None,
        })
    }

    /// Resolves `name` to an [Import] within the context of this module.
    pub fn get_import(&self, name: &str) -> Option<&Import> {
        self.imports.iter().find(|import| import.local_name().as_str() == name)
    }

    /// Same as [Module::get_import], but returns a mutable reference to the [Import].
    pub fn get_import_mut(&mut self, name: &str) -> Option<&mut Import> {
        self.imports.iter_mut().find(|import| import.local_name().as_str() == name)
    }

    /// Get an iterator over imports in this module.
    pub fn imports(&self) -> impl Iterator<Item = &Import> + '_ {
        self.imports.iter()
    }

    /// Same as [Module::imports], but returns mutable references.
    pub fn imports_mut(&mut self) -> impl Iterator<Item = &mut Import> + '_ {
        self.imports.iter_mut()
    }

    /// Takes all imports from this module.
    pub fn take_imports(&mut self) -> Vec<Import> {
        core::mem::take(&mut self.imports)
    }

    /// Get a reference to the set of package identifiers that this module declares a dependency on
    ///
    /// This is only reflects explicit `extern package` declarations of the root project module,
    /// not actual requirements, i.e. it is not authoritative.
    pub fn required_packages(&self) -> &[Ident] {
        &self.extern_packages
    }

    /// Get a reference to the set of submodule declarations in this module.
    pub fn submodules(&self) -> &[SubmoduleDecl] {
        &self.submodules
    }

    /// Get a reference to the items stored in this module
    pub fn items(&self) -> &[Item] {
        &self.items
    }

    /// Returns a mutable iterator over the items in this module.
    /// Note: does not expose `Vec` directly to preserve the `name_map` invariant.
    pub fn items_mut(&mut self) -> impl Iterator<Item = &mut Item> {
        self.name_map_dirty = true;
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
    /// The item returned may be either a locally-defined item, or a re-exported item. See [Item]
    /// for details.
    pub fn get(&self, index: ItemIndex) -> Option<&Item> {
        self.items.get(index.as_usize())
    }

    /// Get the [ItemIndex] for the first item in this module's item table which returns true for
    /// `predicate`.
    pub fn index_of<F>(&self, predicate: F) -> Option<ItemIndex>
    where
        F: FnMut(&Item) -> bool,
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
}

impl core::ops::Index<ItemIndex> for Module {
    type Output = Item;

    #[inline]
    fn index(&self, index: ItemIndex) -> &Self::Output {
        &self.items[index.as_usize()]
    }
}

impl core::ops::IndexMut<ItemIndex> for Module {
    #[inline]
    fn index_mut(&mut self, index: ItemIndex) -> &mut Self::Output {
        self.name_map_dirty = true;
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
            && self.imports == other.imports
            && self.items == other.items
    }
}

/// Debug representation of this module
impl fmt::Debug for Module {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Module")
            .field("docs", &self.docs)
            .field("path", &self.path)
            .field("namespace_decl", &self.namespace_decl)
            .field("kind", &self.kind)
            .field("extern_packages", &self.extern_packages)
            .field("submodules", &self.submodules)
            .field("imports", &self.imports)
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

        doc += nl()
            + const_text("namespace")
            + const_text(" ")
            + display(self.path().to_relative())
            + nl();

        for (i, package) in self.extern_packages.iter().enumerate() {
            if i > 0 {
                doc += nl();
            }
            doc += const_text("extern package") + const_text(" ") + package.render();
        }

        if !self.extern_packages.is_empty() {
            doc += nl();
        }

        for (i, submodule) in self.submodules.iter().enumerate() {
            if i > 0 {
                doc += nl();
            }
            if submodule.visibility.is_public() {
                doc += const_text("pub mod");
            } else {
                doc += const_text("mod");
            }
            doc += const_text(" ") + submodule.name.render();
        }

        if !self.submodules.is_empty() {
            doc += nl();
        }

        for (import_index, import) in self.imports.iter().enumerate() {
            if import_index > 0 {
                doc += nl();
            }
            doc += import.render();
        }

        if !self.imports.is_empty() {
            doc += nl();
        }

        for (item_index, item) in self.items.iter().enumerate() {
            if item_index > 0 {
                doc += nl();
            }
            doc += item.render();
        }

        doc
    }
}
