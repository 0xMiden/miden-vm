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
    Constant, DocString, EnumType, Export, FunctionType, Import, LocalNameResolver, ProcedureIndex,
    ProcedureName, QualifiedProcedureName, ResolvedProcedure, TypeAlias, TypeDecl, Variant,
};
use crate::{
    LibraryNamespace, LibraryPath,
    ast::{self, AliasTarget, Ident, types},
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
    path: LibraryPath,
    /// The kind of module this represents.
    kind: ModuleKind,
    /// The constants defined in the module body.
    pub(crate) constants: Vec<Constant>,
    /// The types defined in the module body.
    pub(crate) types: Vec<TypeDecl>,
    /// The imports defined in the module body.
    pub(crate) imports: Vec<Import>,
    /// The procedures (defined or re-exported) in the module body.
    ///
    /// NOTE: Despite the name, the procedures in this set are not necessarily exported, the
    /// individual procedure item must be checked to determine visibility.
    pub(crate) procedures: Vec<Export>,
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
    pub fn new(kind: ModuleKind, path: LibraryPath) -> Self {
        Self {
            span: Default::default(),
            docs: None,
            path,
            kind,
            constants: Default::default(),
            types: Default::default(),
            imports: Default::default(),
            procedures: Default::default(),
            advice_map: Default::default(),
        }
    }

    /// An alias for creating the default, but empty, `#kernel` [Module].
    pub fn new_kernel() -> Self {
        Self::new(ModuleKind::Kernel, LibraryNamespace::Kernel.into())
    }

    /// An alias for creating the default, but empty, `$exec` [Module].
    pub fn new_executable() -> Self {
        Self::new(ModuleKind::Executable, LibraryNamespace::Exec.into())
    }

    /// Specifies the source span in the source file in which this module was defined, that covers
    /// the full definition of this module.
    pub fn with_span(mut self, span: SourceSpan) -> Self {
        self.span = span;
        self
    }

    /// Sets the [LibraryPath] for this module
    pub fn set_path(&mut self, path: LibraryPath) {
        self.path = path;
    }

    /// Sets the [LibraryNamespace] for this module
    pub fn set_namespace(&mut self, ns: LibraryNamespace) {
        self.path.set_namespace(ns);
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
        for c in self.constants.iter() {
            if c.name == constant.name {
                return Err(SemanticAnalysisError::SymbolConflict {
                    span: constant.span,
                    prev_span: c.span,
                });
            }
        }
        self.constants.push(constant);
        Ok(())
    }

    /// Defines a type alias, raising an error if the alias conflicts with a previous definition
    pub fn define_type(&mut self, ty: TypeAlias) -> Result<(), SemanticAnalysisError> {
        for t in self.types.iter() {
            if t.name() == &ty.name {
                return Err(SemanticAnalysisError::SymbolConflict {
                    span: ty.span(),
                    prev_span: t.span(),
                });
            }
        }
        self.types.push(ty.into());
        Ok(())
    }

    /// Define a new enum type `ty`
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

        if let Some(prev) = self.types.iter().find(|t| t.name() == &alias.name) {
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

            self.define_constant(Constant { span, docs, name, value: discriminant })?;
        }

        self.types.push(alias.into());

        Ok(())
    }

    /// Defines a procedure, raising an error if the procedure is invalid, or conflicts with a
    /// previous definition
    pub fn define_procedure(&mut self, export: Export) -> Result<(), SemanticAnalysisError> {
        if self.is_kernel() && matches!(export, Export::Alias(_)) {
            return Err(SemanticAnalysisError::ReexportFromKernel { span: export.span() });
        }
        if let Some(prev) = self.resolve(export.name()) {
            let prev_span = prev.span();
            Err(SemanticAnalysisError::SymbolConflict { span: export.span(), prev_span })
        } else {
            self.procedures.push(export);
            Ok(())
        }
    }

    /// Defines an import, raising an error if the import is invalid, or conflicts with a previous
    /// definition.
    pub fn define_import(&mut self, import: Import) -> Result<(), SemanticAnalysisError> {
        if let Some(prev_import) = self.resolve_import(&import.name) {
            let prev_span = prev_import.span;
            return Err(SemanticAnalysisError::ImportConflict { span: import.span, prev_span });
        }

        if let Some(prev_defined) = self.procedures.iter().find(|e| e.name().eq(&import.name)) {
            let prev_span = prev_defined.span();
            return Err(SemanticAnalysisError::SymbolConflict { span: import.span, prev_span });
        }

        self.imports.push(import);

        Ok(())
    }
}

/// Parsing
impl Module {
    /// Parse a [Module], `name`, of the given [ModuleKind], from `source_file`.
    pub fn parse(
        name: LibraryPath,
        kind: ModuleKind,
        source_file: Arc<SourceFile>,
    ) -> Result<Box<Self>, Report> {
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
    /// Get the name of this specific module, i.e. the last component of the [LibraryPath] that
    /// represents the fully-qualified name of the module, e.g. `u64` in `std::math::u64`
    pub fn name(&self) -> &str {
        self.path.last()
    }

    /// Get the fully-qualified name of this module, e.g. `std::math::u64`
    pub fn path(&self) -> &LibraryPath {
        &self.path
    }

    /// Get the namespace of this module, e.g. `std` in `std::math::u64`
    pub fn namespace(&self) -> &LibraryNamespace {
        self.path.namespace()
    }

    /// Returns true if this module belongs to the provided namespace.
    pub fn is_in_namespace(&self, namespace: &LibraryNamespace) -> bool {
        self.path.namespace() == namespace
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
    pub fn constants(&self) -> core::slice::Iter<'_, Constant> {
        self.constants.iter()
    }

    /// Same as [Module::constants], but returns mutable references.
    pub fn constants_mut(&mut self) -> core::slice::IterMut<'_, Constant> {
        self.constants.iter_mut()
    }

    /// Get an iterator over the types defined in this module.
    pub fn types(&self) -> core::slice::Iter<'_, TypeDecl> {
        self.types.iter()
    }

    /// Same as [Module::types], but returns mutable references.
    pub fn types_mut(&mut self) -> core::slice::IterMut<'_, TypeDecl> {
        self.types.iter_mut()
    }

    /// Get an iterator over the procedures defined in this module.
    ///
    /// The entity returned is an [Export], which abstracts over locally-defined procedures and
    /// re-exported procedures from imported modules.
    pub fn procedures(&self) -> core::slice::Iter<'_, Export> {
        self.procedures.iter()
    }

    /// Same as [Module::procedures], but returns mutable references.
    pub fn procedures_mut(&mut self) -> core::slice::IterMut<'_, Export> {
        self.procedures.iter_mut()
    }

    /// Returns procedures exported from this module.
    ///
    /// Each exported procedure is represented by its local procedure index and a fully qualified
    /// name.
    pub fn exported_procedures(
        &self,
    ) -> impl Iterator<Item = (ProcedureIndex, QualifiedProcedureName)> + '_ {
        self.procedures.iter().enumerate().filter_map(|(proc_idx, p)| {
            // skip un-exported procedures
            if !p.visibility().is_exported() {
                return None;
            }

            let proc_idx = ProcedureIndex::new(proc_idx);
            let fqn = QualifiedProcedureName::new(self.path().clone(), p.name().clone());

            Some((proc_idx, fqn))
        })
    }

    /// Gets the type signature for the given [ProcedureIndex], if available.
    pub fn procedure_signature(&self, id: ProcedureIndex) -> Option<&FunctionType> {
        self.procedures[id.as_usize()].signature()
    }

    /// Get an iterator over the imports declared in this module.
    ///
    /// See [Import] for details on what information is available for imports.
    pub fn imports(&self) -> core::slice::Iter<'_, Import> {
        self.imports.iter()
    }

    /// Same as [Self::imports], but returns mutable references to each import.
    pub fn imports_mut(&mut self) -> core::slice::IterMut<'_, Import> {
        self.imports.iter_mut()
    }

    /// Get an iterator over the "dependencies" of a module, i.e. what library namespaces we expect
    /// to find imported procedures in.
    ///
    /// For example, if we have imported `std::math::u64`, then we would expect to find a library
    /// on disk named `std.masl`, although that isn't a strict requirement. This notion of
    /// dependencies may go away with future packaging-related changed.
    pub fn dependencies(&self) -> impl Iterator<Item = &LibraryNamespace> {
        self.import_paths().map(|import| import.namespace())
    }

    /// Get the procedure at `index` in this module's procedure table.
    ///
    /// The procedure returned may be either a locally-defined procedure, or a re-exported
    /// procedure. See [Export] for details.
    pub fn get(&self, index: ProcedureIndex) -> Option<&Export> {
        self.procedures.get(index.as_usize())
    }

    /// Get the [ProcedureIndex] for the first procedure in this module's procedure table which
    /// returns true for `predicate`.
    pub fn index_of<F>(&self, predicate: F) -> Option<ProcedureIndex>
    where
        F: FnMut(&Export) -> bool,
    {
        self.procedures.iter().position(predicate).map(ProcedureIndex::new)
    }

    /// Get the [ProcedureIndex] for the procedure whose name is `name` in this module's procedure
    /// table, _if_ that procedure is exported.
    ///
    /// Non-exported procedures can be retrieved by using [Module::index_of].
    pub fn index_of_name(&self, name: &ProcedureName) -> Option<ProcedureIndex> {
        self.index_of(|p| p.name() == name && p.visibility().is_exported())
    }

    /// Resolves `name` to a procedure within the local scope of this module
    pub fn resolve(&self, name: &ProcedureName) -> Option<ResolvedProcedure> {
        let index =
            self.procedures.iter().position(|p| p.name() == name).map(ProcedureIndex::new)?;
        match &self.procedures[index.as_usize()] {
            Export::Procedure(proc) => {
                Some(ResolvedProcedure::Local(Span::new(proc.name().span(), index)))
            },
            Export::Alias(alias) => match alias.target() {
                AliasTarget::MastRoot(digest) => Some(ResolvedProcedure::MastRoot(**digest)),
                AliasTarget::ProcedurePath(path) | AliasTarget::AbsoluteProcedurePath(path) => {
                    Some(ResolvedProcedure::External(path.clone()))
                },
            },
        }
    }

    /// Construct a search structure that can resolve procedure names local to this module
    pub fn resolver(&self) -> LocalNameResolver {
        LocalNameResolver::from_iter(self.procedures.iter().enumerate().map(|(i, p)| match p {
            Export::Procedure(p) => (
                p.name().clone(),
                ResolvedProcedure::Local(Span::new(p.name().span(), ProcedureIndex::new(i))),
            ),
            Export::Alias(p) => {
                let target = match p.target() {
                    AliasTarget::MastRoot(digest) => ResolvedProcedure::MastRoot(**digest),
                    AliasTarget::ProcedurePath(path) | AliasTarget::AbsoluteProcedurePath(path) => {
                        ResolvedProcedure::External(path.clone())
                    },
                };
                (p.name().clone(), target)
            },
        }))
        .with_imports(
            self.imports
                .iter()
                .map(|import| (import.name.clone(), Span::new(import.span(), import.path.clone()))),
        )
    }

    /// Resolves `module_name` to an [Import] within the context of this module
    pub fn resolve_import(&self, module_name: &Ident) -> Option<&Import> {
        self.imports.iter().find(|import| &import.name == module_name)
    }

    /// Same as [Module::resolve_import], but returns a mutable reference to the [Import]
    pub fn resolve_import_mut(&mut self, module_name: &Ident) -> Option<&mut Import> {
        self.imports.iter_mut().find(|import| &import.name == module_name)
    }

    /// Return an iterator over the paths of all imports in this module
    pub fn import_paths(&self) -> impl Iterator<Item = &LibraryPath> + '_ {
        self.imports.iter().map(|import| &import.path)
    }

    /// Resolves a user-expressed type, `ty`, to a concrete type
    pub fn resolve_type(&self, ty: &ast::TypeExpr) -> Option<types::Type> {
        match ty {
            ast::TypeExpr::Ref(name) => match self.types.iter().find(|t| t.name() == name)? {
                ast::TypeDecl::Alias(alias) => self.resolve_type(&alias.ty),
                ast::TypeDecl::Enum(enum_ty) => Some(enum_ty.ty().clone()),
            },
            ast::TypeExpr::Primitive(t) => Some(t.inner().clone()),
            ast::TypeExpr::Array(t) => {
                let elem = self.resolve_type(&t.elem)?;
                Some(types::Type::Array(Arc::new(types::ArrayType::new(elem, t.arity))))
            },
            ast::TypeExpr::Ptr(ty) => {
                let pointee = self.resolve_type(&ty.pointee)?;
                Some(types::Type::Ptr(Arc::new(types::PointerType::new(pointee))))
            },
            ast::TypeExpr::Struct(t) => {
                let mut fields = Vec::with_capacity(t.fields.len());
                for field in t.fields.iter() {
                    let field_ty = self.resolve_type(&field.ty)?;
                    fields.push(field_ty);
                }
                Some(types::Type::Struct(Arc::new(types::StructType::new(fields))))
            },
        }
    }
}

impl core::ops::Index<ProcedureIndex> for Module {
    type Output = Export;

    #[inline]
    fn index(&self, index: ProcedureIndex) -> &Self::Output {
        &self.procedures[index.as_usize()]
    }
}

impl core::ops::IndexMut<ProcedureIndex> for Module {
    #[inline]
    fn index_mut(&mut self, index: ProcedureIndex) -> &mut Self::Output {
        &mut self.procedures[index.as_usize()]
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
            && self.constants == other.constants
            && self.types == other.types
            && self.imports == other.imports
            && self.procedures == other.procedures
    }
}

/// Debug representation of this module
impl fmt::Debug for Module {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Module")
            .field("docs", &self.docs)
            .field("path", &self.path)
            .field("kind", &self.kind)
            .field("constants", &self.constants)
            .field("types", &self.types)
            .field("imports", &self.imports)
            .field("procedures", &self.procedures)
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

        for (i, import) in self.imports.iter().enumerate() {
            if i > 0 {
                doc += nl();
            }
            doc += import.render();
        }

        if !self.imports.is_empty() {
            doc += nl();
        }

        for (i, constant) in self.constants.iter().enumerate() {
            if i > 0 {
                doc += nl();
            }
            doc += constant.render();
        }

        if !self.constants.is_empty() {
            doc += nl();
        }

        let mut export_index = 0;
        for export in self.procedures.iter() {
            if export.is_main() {
                continue;
            }
            if export_index > 0 {
                doc += nl();
            }
            doc += export.render();
            export_index += 1;
        }

        if let Some(main) = self.procedures().find(|p| p.is_main()) {
            if export_index > 0 {
                doc += nl();
            }
            doc += main.render();
        }

        doc
    }
}
