use alloc::sync::Arc;

use miden_assembly_syntax::{
    ast::types::FunctionType,
    debuginfo::{SourceManager, SourceSpan, Spanned},
};
use miden_core::{Word, mast::MastNodeId};

use super::GlobalProcedureIndex;
use crate::{
    LibraryPath,
    ast::{ProcedureName, QualifiedProcedureName, Visibility},
};

// PROCEDURE CONTEXT
// ================================================================================================

/// Information about a procedure currently being compiled.
pub struct ProcedureContext {
    source_manager: Arc<dyn SourceManager>,
    gid: GlobalProcedureIndex,
    is_program_entrypoint: bool,
    span: SourceSpan,
    name: QualifiedProcedureName,
    signature: Option<Arc<FunctionType>>,
    visibility: Visibility,
    is_kernel: bool,
    num_locals: u16,
}

// ------------------------------------------------------------------------------------------------
/// Constructors
impl ProcedureContext {
    pub fn new(
        gid: GlobalProcedureIndex,
        is_program_entrypoint: bool,
        name: QualifiedProcedureName,
        visibility: Visibility,
        signature: Option<Arc<FunctionType>>,
        is_kernel: bool,
        source_manager: Arc<dyn SourceManager>,
    ) -> Self {
        Self {
            source_manager,
            gid,
            is_program_entrypoint,
            span: name.span(),
            name,
            visibility,
            signature,
            is_kernel,
            num_locals: 0,
        }
    }

    /// Sets the number of locals to allocate for the procedure.
    pub fn with_num_locals(mut self, num_locals: u16) -> Self {
        self.num_locals = num_locals;
        self
    }

    pub fn with_span(mut self, span: SourceSpan) -> Self {
        self.span = span;
        self
    }
}

// ------------------------------------------------------------------------------------------------
/// Public accessors
impl ProcedureContext {
    pub fn id(&self) -> GlobalProcedureIndex {
        self.gid
    }

    pub fn is_program_entrypoint(&self) -> bool {
        self.is_program_entrypoint
    }

    pub fn name(&self) -> &QualifiedProcedureName {
        &self.name
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

    #[allow(unused)]
    pub fn module(&self) -> &LibraryPath {
        &self.name.module
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
    /// The passed-in `mast_root` defines the MAST root of the procedure's body while
    /// `mast_node_id` specifies the ID of the procedure's body node in the MAST forest in
    /// which the procedure is defined. Note that if the procedure is re-exported (i.e., the body
    /// of the procedure is defined in some other MAST forest) `mast_node_id` will point to a
    /// single `External` node.
    ///
    /// <div class="warning">
    /// `mast_root` and `mast_node_id` must be consistent. That is, the node located in the MAST
    /// forest under `mast_node_id` must have the digest equal to the `mast_root`.
    /// </div>
    pub fn into_procedure(self, mast_root: Word, mast_node_id: MastNodeId) -> Procedure {
        Procedure::new(
            self.name,
            self.visibility,
            self.signature,
            self.num_locals as u32,
            mast_root,
            mast_node_id,
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
/// - The set of MAST roots invoked by this procedure.
/// - The original source span and file of the procedure (if available).
#[derive(Clone, Debug)]
pub struct Procedure {
    span: SourceSpan,
    path: QualifiedProcedureName,
    signature: Option<Arc<FunctionType>>,
    visibility: Visibility,
    num_locals: u32,
    /// The MAST root of the procedure.
    mast_root: Word,
    /// The MAST node id which resolves to the above MAST root.
    body_node_id: MastNodeId,
}

// ------------------------------------------------------------------------------------------------
/// Constructors
impl Procedure {
    fn new(
        path: QualifiedProcedureName,
        visibility: Visibility,
        signature: Option<Arc<FunctionType>>,
        num_locals: u32,
        mast_root: Word,
        body_node_id: MastNodeId,
    ) -> Self {
        Self {
            span: SourceSpan::default(),
            path,
            visibility,
            signature,
            num_locals,
            mast_root,
            body_node_id,
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
    /// Returns a reference to the name of this procedure
    #[allow(unused)]
    pub fn name(&self) -> &ProcedureName {
        &self.path.name
    }

    /// Returns a reference to the fully-qualified name of this procedure
    pub fn fully_qualified_name(&self) -> &QualifiedProcedureName {
        &self.path
    }

    /// Returns the visibility of this procedure as expressed in the original source code
    pub fn visibility(&self) -> Visibility {
        self.visibility
    }

    /// Returns a reference to the fully-qualified module path of this procedure
    pub fn path(&self) -> &LibraryPath {
        &self.path.module
    }

    /// Returns a reference to the type signature of this procedure
    pub fn signature(&self) -> Option<Arc<FunctionType>> {
        self.signature.clone()
    }

    /// Returns the number of memory locals reserved by the procedure.
    pub fn num_locals(&self) -> u32 {
        self.num_locals
    }

    /// Returns the root of this procedure's MAST.
    pub fn mast_root(&self) -> Word {
        self.mast_root
    }

    /// Returns a reference to the MAST node ID of this procedure.
    pub fn body_node_id(&self) -> MastNodeId {
        self.body_node_id
    }
}

impl Spanned for Procedure {
    fn span(&self) -> SourceSpan {
        self.span
    }
}
