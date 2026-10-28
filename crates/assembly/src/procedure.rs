use alloc::sync::Arc;

use miden_assembly_syntax::{
    ast::{Attribute, AttributeSet, MetaExpr, Path, PathBuf, Visibility, types::FunctionType},
    debuginfo::{SourceManager, SourceSpan, Spanned},
    diagnostics::Report,
};
use miden_core::Word;

use super::{
    GlobalItemIndex,
    assembler::{MAX_PROC_LOCALS, error::AssemblerError},
    mast_forest_builder::{MastNodeRef, MastNodeUse, SourceNodeRef},
};

// PROCEDURE CONTEXT
// ================================================================================================

/// Information about a procedure currently being compiled.
pub struct ProcedureContext {
    source_manager: Arc<dyn SourceManager>,
    gid: GlobalItemIndex,
    is_program_entrypoint: bool,
    span: SourceSpan,
    path: Arc<Path>,
    signature: Option<Arc<FunctionType>>,
    attributes: AttributeSet,
    visibility: Visibility,
    is_kernel: bool,
    num_locals: u16,
}

// ------------------------------------------------------------------------------------------------
/// Constructors
impl ProcedureContext {
    pub fn new(
        gid: GlobalItemIndex,
        is_program_entrypoint: bool,
        path: Arc<Path>,
        visibility: Visibility,
        signature: Option<Arc<FunctionType>>,
        is_kernel: bool,
        source_manager: Arc<dyn SourceManager>,
    ) -> Self {
        Self {
            source_manager,
            gid,
            is_program_entrypoint,
            span: SourceSpan::UNKNOWN,
            path,
            visibility,
            signature,
            attributes: Default::default(),
            is_kernel,
            num_locals: 0,
        }
    }

    /// Sets the number of locals to allocate for the procedure.
    ///
    /// Returns an error if `num_locals` exceeds `MAX_PROC_LOCALS`, the largest count that
    /// stays representable in a `u16` once rounded up to a word boundary during frame-pointer
    /// codegen. The text parser enforces this on `@locals(..)`, but procedures built directly
    /// via the AST bypass the parser. So the limit is enforced here for all callers.
    ///
    /// Call [`Self::with_span`] first so the error can point at the procedure definition.
    pub fn with_num_locals(mut self, num_locals: u16) -> Result<Self, Report> {
        if num_locals > MAX_PROC_LOCALS {
            let source_file = self.source_manager.get(self.span.source_id()).ok();
            return Err(Report::new(AssemblerError::TooManyProcedureLocals {
                span: self.span,
                source_file,
                max_locals: MAX_PROC_LOCALS,
                num_locals,
            }));
        }
        self.num_locals = num_locals;
        Ok(self)
    }

    pub fn with_span(mut self, span: SourceSpan) -> Self {
        self.span = span;
        self
    }

    /// Sets the attributes attached to this procedure.
    pub fn with_attributes(mut self, attributes: AttributeSet) -> Self {
        self.attributes = attributes;
        self
    }
}

// ------------------------------------------------------------------------------------------------
/// Public accessors
impl ProcedureContext {
    pub fn id(&self) -> GlobalItemIndex {
        self.gid
    }

    pub fn is_program_entrypoint(&self) -> bool {
        self.is_program_entrypoint
    }

    pub fn path(&self) -> &Arc<Path> {
        &self.path
    }

    pub fn signature(&self) -> Option<Arc<FunctionType>> {
        self.signature.clone()
    }

    pub fn set_signature(&mut self, signature: Option<Arc<FunctionType>>) {
        self.signature = signature;
    }

    pub fn num_locals(&self) -> u16 {
        self.num_locals
    }

    pub fn module(&self) -> &Path {
        self.path.parent().unwrap()
    }

    /// Returns true if the procedure is being assembled for a kernel.
    pub fn is_kernel(&self) -> bool {
        self.is_kernel
    }

    #[inline(always)]
    pub fn source_manager(&self) -> &dyn SourceManager {
        self.source_manager.as_ref()
    }
}

// ------------------------------------------------------------------------------------------------
/// State mutators
impl ProcedureContext {
    /// Transforms this procedure context into a [Procedure].
    ///
    /// The passed-in `mast_root` defines the MAST root of the procedure's body while `body_node`
    /// specifies the assembly-time reference to the procedure's body node.
    ///
    /// <div class="warning">
    /// `mast_root` and `body_node` must be consistent. That is, `body_node` must resolve to a MAST
    /// node whose digest equals `mast_root`.
    /// </div>
    pub(crate) fn into_procedure(self, mast_root: Word, body_node: MastNodeUse) -> Procedure {
        let is_syscall = self.is_kernel && self.visibility.is_public();
        Procedure::new(
            self.path,
            self.visibility,
            self.signature,
            self.attributes,
            is_syscall,
            self.num_locals as u32,
            mast_root,
            body_node,
        )
        .with_span(self.span)
    }
}

impl Spanned for ProcedureContext {
    fn span(&self) -> SourceSpan {
        self.span
    }
}

// PROCEDURE
// ================================================================================================

/// A compiled Miden Assembly procedure, consisting of MAST info and basic metadata.
///
/// Procedure metadata includes:
///
/// - Fully-qualified path of the procedure in Miden Assembly (if known).
/// - Number of procedure locals to allocate.
/// - The visibility of the procedure (e.g. public/private/syscall)
/// - The attributes attached to the procedure.
/// - The set of MAST roots invoked by this procedure.
/// - The original source span and file of the procedure (if available).
#[derive(Clone, Debug)]
pub struct Procedure {
    span: SourceSpan,
    path: Arc<Path>,
    signature: Option<Arc<FunctionType>>,
    attributes: AttributeSet,
    visibility: Visibility,
    is_syscall: bool,
    num_locals: u32,
    /// The MAST root of the procedure.
    mast_root: Word,
    /// The assembly-time node reference which resolves to the above MAST root.
    body_node_ref: MastNodeRef,
    /// The exact source/debug occurrence for this procedure body.
    body_source_ref: SourceNodeRef,
}

// ------------------------------------------------------------------------------------------------
/// Constructors
impl Procedure {
    fn new(
        path: Arc<Path>,
        visibility: Visibility,
        signature: Option<Arc<FunctionType>>,
        attributes: AttributeSet,
        is_syscall: bool,
        num_locals: u32,
        mast_root: Word,
        body_node: MastNodeUse,
    ) -> Self {
        Self {
            span: SourceSpan::default(),
            path,
            visibility,
            signature,
            attributes,
            is_syscall,
            num_locals,
            mast_root,
            body_node_ref: body_node.node_ref(),
            body_source_ref: body_node.source_ref(),
        }
    }

    pub(crate) fn with_span(mut self, span: SourceSpan) -> Self {
        self.span = span;
        self
    }
}

// ------------------------------------------------------------------------------------------------
/// Public accessors
impl Procedure {
    /// Returns source span of this procedure.
    pub fn span(&self) -> &SourceSpan {
        &self.span
    }

    /// Returns a reference to the fully-qualified name of this procedure
    pub fn path(&self) -> &Arc<Path> {
        &self.path
    }

    /// Returns true if this procedure is a syscallable procedure
    #[inline(always)]
    pub const fn is_syscall(&self) -> bool {
        self.is_syscall
    }

    /// Returns the visibility of this procedure as expressed in the original source code
    pub fn visibility(&self) -> Visibility {
        self.visibility
    }

    /// Returns a reference to the fully-qualified module path of this procedure
    pub fn module(&self) -> &Path {
        self.path.parent().unwrap()
    }

    /// Returns a reference to the type signature of this procedure
    pub fn signature(&self) -> Option<Arc<FunctionType>> {
        self.signature.clone()
    }

    /// Returns the attributes attached to this procedure.
    pub fn attributes(&self) -> &AttributeSet {
        &self.attributes
    }

    /// Returns the fully-qualified `@source_name`, if present.
    ///
    /// The returned path is formed by joining the procedure's module path and `@source_name`.
    ///
    /// # `@source_name` specification
    ///
    /// The attribute must contain exactly one quoted string.
    ///
    /// `@source_name` allows a producer to preserve a source-level function name while giving the
    /// emitted Miden Assembly procedure a distinct symbol. This is useful when multiple source
    /// functions share a name but require unique assembler symbols.
    ///
    /// Producers emitting this attribute must respect these requirements:
    ///
    /// - Give every emitted procedure whose source-level name is duplicated a distinct,
    ///   deterministic assembler symbol.
    /// - Attach `@source_name("original name")` to every such procedure, using the original
    ///   source-level name.
    /// - Do not attach `@source_name` to procedures with a unique source-level name or without a
    ///   source-level name.
    ///
    /// Duplicate `@source_name` values are valid. They identify the source-facing name; the
    /// separately recorded unique linkage name identifies the corresponding assembler procedure.
    ///
    /// # Errors
    ///
    /// Returns an error if a `@source_name` attribute is present, but is not of the form
    /// `@source_name("...")`.
    pub fn source_name_fully_qualified(
        &self,
        source_manager: &dyn SourceManager,
    ) -> Result<Option<PathBuf>, Report> {
        let Some(attribute) = self.attributes.get("source_name") else {
            return Ok(None);
        };

        if let Attribute::List(list) = attribute
            && let [MetaExpr::String(name)] = list.as_slice()
        {
            return Ok(Some(self.path.parent().unwrap().join(name)));
        }

        let span = attribute.span();
        Err(Report::new(AssemblerError::InvalidSourceNameAttribute {
            span,
            source_file: source_manager.get(span.source_id()).ok(),
        }))
    }

    /// Returns the number of memory locals reserved by the procedure.
    pub fn num_locals(&self) -> u32 {
        self.num_locals
    }

    /// Returns the root of this procedure's MAST.
    pub fn mast_root(&self) -> Word {
        self.mast_root
    }

    /// Returns the assembly-time node reference of this procedure.
    pub(crate) fn body_node_ref(&self) -> MastNodeRef {
        self.body_node_ref
    }

    pub(crate) fn body_node_use(&self) -> MastNodeUse {
        MastNodeUse::new(self.body_node_ref, self.body_source_ref)
    }

    pub(crate) fn body_source_ref(&self) -> SourceNodeRef {
        self.body_source_ref
    }
}

impl Spanned for Procedure {
    fn span(&self) -> SourceSpan {
        self.span
    }
}

#[cfg(test)]
mod tests {
    use alloc::{sync::Arc, vec};

    use miden_assembly_syntax::{
        PathBuf,
        ast::{Attribute, Ident, MetaExpr},
        debuginfo::{DefaultSourceManager, SourceLanguage, Uri},
    };

    use super::*;

    /// Constructs a [Procedure] with `attrs` attached, for testing attribute accessors.
    fn procedure_with_attributes(attrs: vec::IntoIter<Attribute>) -> Procedure {
        Procedure::new(
            Arc::from(PathBuf::new("::test::module::foo").unwrap()),
            Visibility::Private,
            None,
            AttributeSet::new(attrs),
            false,
            0,
            Word::default(),
            MastNodeUse::new(MastNodeRef::from(0), SourceNodeRef::from(0)),
        )
    }

    #[test]
    fn source_name_fully_qualified_is_none_without_attribute() {
        let source_manager = DefaultSourceManager::default();
        let procedure = procedure_with_attributes(vec![].into_iter());

        assert_eq!(procedure.source_name_fully_qualified(&source_manager).unwrap(), None);
    }

    #[test]
    fn source_name_fully_qualified_returns_quoted_string_joined_to_module_path() {
        let source_manager = DefaultSourceManager::default();
        let attribute = Attribute::from_iter(
            Ident::new("source_name").unwrap(),
            [MetaExpr::String(Ident::new("bar").unwrap())],
        );
        let procedure = procedure_with_attributes(vec![attribute].into_iter());

        assert_eq!(
            procedure.source_name_fully_qualified(&source_manager).unwrap(),
            Some(PathBuf::new("::test::module::bar").unwrap()),
        );
    }

    #[test]
    fn malformed_source_name_attributes_are_rejected() {
        let source_manager = DefaultSourceManager::default();
        let file = source_manager.load(
            SourceLanguage::Masm,
            Uri::new("test.masm"),
            "@source_name(unquoted)".into(),
        );
        let span = SourceSpan::new(file.id(), 0..19);

        // Generate some malformed `@source_name` attributes
        let malformed = vec![
            Attribute::Marker(Ident::new("source_name").unwrap()),
            // `@source_name(unquoted)`
            Attribute::from_iter(
                Ident::new("source_name").unwrap(),
                [MetaExpr::Ident(Ident::new("unquoted").unwrap())],
            ),
            // `@source_name("one", "two")`
            Attribute::from_iter(
                Ident::new("source_name").unwrap(),
                [
                    MetaExpr::String(Ident::new("one").unwrap()),
                    MetaExpr::String(Ident::new("two").unwrap()),
                ],
            ),
            // `@source_name(value = "named")`
            Attribute::from_iter(
                Ident::new("source_name").unwrap(),
                [(Ident::new("value").unwrap(), MetaExpr::String(Ident::new("named").unwrap()))],
            ),
        ];

        for attribute in malformed {
            let procedure = procedure_with_attributes(vec![attribute.with_span(span)].into_iter());
            let error = procedure.source_name_fully_qualified(&source_manager).unwrap_err();

            match error.downcast_ref::<AssemblerError>() {
                Some(AssemblerError::InvalidSourceNameAttribute { source_file, .. }) => {
                    // The error must be attributed to the file in which the attribute occurred
                    assert_eq!(source_file.as_ref(), Some(&file));
                },
                unexpected => panic!("expected InvalidSourceNameAttribute, got {unexpected:?}"),
            }
        }
    }
}
