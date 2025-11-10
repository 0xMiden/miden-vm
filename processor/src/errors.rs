// Allow unused assignments - required by miette::Diagnostic derive macro
#![allow(unused_assignments)]

//! # Error Architecture
//!
//! This module implements a two-tier error boundary pattern that separates "what went wrong"
//! (logical error semantics) from "where it went wrong" (diagnostic source context).
//!
//! ## Error Types
//!
//! - **[`OperationError`]**: Context-free errors from operations. Contains runtime data (clock
//!   cycles, values, addresses) but NO source locations. Returned by all operation implementations.
//!
//! - **[`ExecutionError`]**: User-facing errors with source spans and file references. Either wraps
//!   an `OperationError` with source context via the `OperationError` variant, or represents
//!   program-level errors (e.g., `CycleLimitExceeded`, `ProgramAlreadyExecuted`).
//!
//! ## Design Principles
//!
//! 1. **Operations return `OperationError`** - No error context threading through signatures. Each
//!    operation implementation is context-free and focuses purely on the error condition.
//!
//! 2. **Boundaries wrap with context** - Error context is added at boundaries where it's available
//!    (decoders, fast processor, basic block executors) using [`ErrorContext::wrap_op_err`].
//!
//! 3. **Errors propagate naturally** - No intermediate rewrapping. When a dyncall or call fails
//!    during callee execution, the error bubbles up with its original source context preserved,
//!    pointing to the actual failing instruction, not the call site.
//!
//! 4. **Subsystem errors appear in `OperationError` only** - Errors from chiplets ([`MemoryError`],
//!    [`AceError`]) are wrapped in `OperationError` at chiplet boundaries, then wrapped again in
//!    `ExecutionError` at operation boundaries. This creates a consistent error chain without
//!    ambiguity.
//!
//! ## Example Flow
//!
//! ```text
//! // 1. Operation (context-free)
//! fn op_u32add(&mut self) -> Result<(), OperationError> {
//!     if !is_valid {
//!         return Err(OperationError::NotU32Values { values, err_code });
//!     }
//!     Ok(())
//! }
//!
//! // 2. Boundary (adds context)
//! let err_ctx = err_ctx!(program, node, host, op_idx, self.clk);
//! self.execute_op(op)
//!     .map_err(|err| err_ctx.wrap_op_err(err))?;
//! ```
//!
//! ## Error Context Feature Flag
//!
//! The `no_err_ctx` feature flag allows compile-time elimination of error context for
//! performance-critical builds. When enabled, the `err_ctx!()` macro expands to `()` and all
//! context operations become no-ops.

use alloc::{boxed::Box, sync::Arc, vec::Vec};

use miden_air::RowIndex;
use miden_core::{
    EventId, EventName, Felt, QuadFelt, Word,
    mast::{DecoratorId, MastForest, MastNodeErrorContext, MastNodeId},
    stack::MIN_STACK_DEPTH,
    utils::to_hex,
};
use miden_debug_types::{SourceFile, SourceSpan};
use miden_utils_diagnostics::{Diagnostic, miette};
use winter_prover::ProverError;

use crate::{BaseHost, EventError, MemoryError, host::advice::AdviceError};
// EXECUTION ERROR
// ================================================================================================

#[derive(Debug, thiserror::Error, Diagnostic)]
pub enum ExecutionError {
    #[error("operation error at clock cycle {clk}")]
    #[diagnostic()]
    OperationError {
        clk: RowIndex,
        #[label]
        label: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
        #[source]
        err: Box<OperationError>,
    },
    #[error("operation error at clock cycle {clk} (source location unavailable)")]
    #[diagnostic(help(
        "this error occurred during execution, but source location information is not available. This typically happens when loading external MAST forests without debug information"
    ))]
    OperationErrorNoContext {
        clk: RowIndex,
        #[source]
        err: Box<OperationError>,
    },
    #[error("exceeded the allowed number of max cycles {0}")]
    CycleLimitExceeded(u32),
    #[error("attempted to add event handler for '{0}' (already registered)")]
    DuplicateEventHandler(EventName),
    #[error("attempted to add event handler for '{0}' (reserved system event)")]
    ReservedEventNamespace(EventName),
    #[error("failed to execute the program for internal reason: {0}")]
    FailedToExecuteProgram(&'static str),
    #[error("stack should have at most {MIN_STACK_DEPTH} elements at the end of program execution, but had {} elements", MIN_STACK_DEPTH + .0)]
    OutputStackOverflow(usize),
    #[error("a program has already been executed in this process")]
    ProgramAlreadyExecuted,
    #[error("program initialization failed")]
    ProgramInitializationFailed(#[source] AdviceError),
    #[error("proof generation failed")]
    ProverError(#[source] ProverError),
    #[error("execution yielded unexpected precompiles")]
    UnexpectedPrecompiles,
}

impl AsRef<dyn Diagnostic> for ExecutionError {
    fn as_ref(&self) -> &(dyn Diagnostic + 'static) {
        self
    }
}

// OPERATION ERROR
// ================================================================================================

#[derive(Debug, thiserror::Error, Diagnostic)]
pub enum OperationError {
    #[error("advice error")]
    #[diagnostic()]
    AdviceError(#[source] AdviceError),
    #[error("external node with mast root {0} resolved to an external node")]
    CircularExternalNode(Word),
    #[error("decorator id {0} does not exist in MAST forest")]
    DecoratorNotFoundInForest(DecoratorId),
    #[error("node id {0} does not exist in MAST forest")]
    MastNodeNotFoundInForest(MastNodeId),
    #[error("no MAST forest contains the procedure with root digest {root_digest}")]
    NoMastForestWithProcedure { root_digest: Word },
    #[error(
        "MAST forest in host indexed by procedure root {root_digest} doesn't contain that root"
    )]
    MalformedMastForestInHost { root_digest: Word },
    #[error(
        "dynamic execution failed: code block with root {hex} not found in program",
        hex = .digest.to_hex()
    )]
    #[diagnostic(help(
        "dynexec/dyncall requires the target code block to be included in the MAST forest. Ensure the procedure was compiled into the program"
    ))]
    DynamicNodeNotFound { digest: Word },
    #[error(
        "error during processing of event {}",
        match event_name {
            Some(name) => format!("'{}' (ID: {})", name, event_id),
            None => format!("with ID: {}", event_id),
        }
    )]
    EventError {
        event_id: EventId,
        event_name: Option<EventName>,
        #[source]
        error: EventError,
    },
    #[error(
        "assertion failed with error {}",
        match err_msg {
            Some(msg) => format!("message: {msg}"),
            None => format!("code: {err_code}"),
        }
    )]
    #[diagnostic(help(
        "assertions validate program invariants. Review the assertion condition and ensure all prerequisites are met"
    ))]
    FailedAssertion {
        err_code: Felt,
        err_msg: Option<Arc<str>>,
    },
    #[error("stack overflow: maximum stack depth exceeded")]
    #[diagnostic(help(
        "the operand stack has a maximum depth limit. Use fewer nested operations or store intermediate values in memory"
    ))]
    StackOverflow,
    #[error("division by zero")]
    #[diagnostic(help(
        "ensure the divisor (second stack element) is non-zero before division or modulo operations"
    ))]
    DivideByZero,
    #[error(
        "when returning from a call or dyncall, stack depth must be {MIN_STACK_DEPTH}, but was {0}"
    )]
    #[diagnostic(help(
        "ensure the callee procedure returns with exactly {MIN_STACK_DEPTH} elements on the stack"
    ))]
    InvalidStackDepthOnReturn(usize),
    #[error("exceeded the allowed number of max cycles {max_cycles}")]
    CycleLimitExceeded { max_cycles: u32 },
    #[error("logarithm of zero is undefined")]
    #[diagnostic(help("ensure the argument to ilog2 is greater than zero"))]
    LogArgumentZero,
    #[error("malformed signature key: {key_type}")]
    #[diagnostic(help("the secret key associated with the provided public key is malformed"))]
    MalformedSignatureKey { key_type: &'static str },
    #[error(
        "merkle path verification failed for value {value} at index {index} in the Merkle tree with root {root} (error {err})",
        value = to_hex(value.as_bytes()),
        root = to_hex(root.as_bytes()),
        err = match err_msg {
            Some(msg) => format!("message: {msg}"),
            None => format!("code: {err_code}"),
        }
    )]
    MerklePathVerificationFailed {
        value: Word,
        index: Felt,
        root: Word,
        err_code: Felt,
        err_msg: Option<Arc<str>>,
    },
    #[error("conditional operation requires binary value (0 or 1), but stack top contains {0}")]
    #[diagnostic(help(
        "use u32assert2 or comparison operations to ensure stack top is 0 or 1 before conditional operations"
    ))]
    NotBinaryValueIf(Felt),
    #[error("operation requires binary value (0 or 1), but got {0}")]
    #[diagnostic(help("use u32assert2 or comparison operations to ensure the operand is 0 or 1"))]
    NotBinaryValueOp(Felt),
    #[error("loop condition must be a binary value, but got {0}")]
    #[diagnostic(help(
        "this could happen either when first entering the loop, or any subsequent iteration"
    ))]
    NotBinaryValueLoop(Felt),
    #[error("operation expected u32 values, but got values: {values:?} (error code: {err_code})")]
    NotU32Values { values: Vec<Felt>, err_code: Felt },
    #[error("operand stack input is {0} but it is expected to fit in a u32")]
    NotU32StackValue(u64),
    #[error("smt node {node_hex} not found", node_hex = to_hex(node.as_bytes()))]
    SmtNodeNotFound { node: Word },
    #[error(
        "expected pre-image length of node {node_hex} to be a multiple of 8 but was {preimage_len}",
        node_hex = to_hex(node.as_bytes())
    )]
    SmtNodePreImageNotValid { node: Word, preimage_len: usize },
    #[error(
        "syscall target not found: procedure {hex} is not in the kernel",
        hex = to_hex(proc_root.as_bytes())
    )]
    #[diagnostic(help(
        "syscalls can only invoke procedures that were compiled into the kernel. Check that the target procedure is part of the kernel module"
    ))]
    SyscallTargetNotInKernel { proc_root: Word },
    #[error(transparent)]
    #[diagnostic(transparent)]
    AceChipError(AceError),
    #[error("FRI domain segment value cannot exceed 3, but was {0}")]
    InvalidFriDomainSegment(u64),
    #[error("degree-respecting projection is inconsistent: expected {0} but was {1}")]
    InvalidFriLayerFolding(QuadFelt, QuadFelt),
    #[error("memory error")]
    #[diagnostic()]
    MemoryError(#[source] MemoryError),
}

// ACE ERROR
// ================================================================================================

#[derive(Debug, thiserror::Error, Diagnostic)]
pub enum AceError {
    #[error("invalid variable count {0}: must be word-aligned (multiple of 4) and non-zero")]
    #[diagnostic(help(
        "ACE circuits require variable counts that are multiples of 4 to align with word boundaries"
    ))]
    NumVarIsNotWordAlignedOrIsEmpty(u64),
    #[error("invalid evaluation gate count {0}: must be word-aligned (multiple of 4) and non-zero")]
    #[diagnostic(help("ACE circuits require evaluation gate counts that are multiples of 4"))]
    NumEvalIsNotWordAlignedOrIsEmpty(u64),
    #[error("arithmetic circuit constraint failed: circuit does not evaluate to zero")]
    #[diagnostic(help(
        "the provided witness values do not satisfy the circuit constraints. Verify the circuit definition and witness generation"
    ))]
    CircuitNotEvaluateZero,
    #[error("failed to read from memory")]
    FailedMemoryRead(#[source] MemoryError),
    #[error("failed to decode instruction")]
    FailedDecodeInstruction,
    #[error("failed to read from the wiring bus")]
    FailedWireBusRead,
    #[error("wire count {0} exceeds maximum limit of 2^30")]
    #[diagnostic(help("reduce circuit complexity or split into multiple smaller circuits"))]
    TooManyWires(u64),
}

// ERROR CONTEXT
// ===============================================================================================

/// Trait defining the interface for error context providers.
///
/// This trait provides a common interface for error context functionality. Implementations
/// can either eagerly pre-compute source information (like [`ErrorContextImpl`]) or lazily
/// resolve it on demand (like [`OpErrorContext`]).
pub trait ErrorContext {
    /// Returns the label and source file associated with the error context, if available.
    ///
    /// Returns `None` when source context is not available (e.g., when executing code
    /// without debug information).
    ///
    /// # Note
    ///
    /// This method may be expensive for lazy implementations that defer source resolution.
    /// It should typically only be called in error paths.
    fn label_and_source_file(&self) -> Option<(SourceSpan, Option<Arc<SourceFile>>)>;

    /// Resolves source location using the provided host.
    ///
    /// This method is provided for lazy error context implementations that need access
    /// to the host to resolve source locations. The default implementation delegates to
    /// `label_and_source_file()` for backwards compatibility.
    ///
    /// # Arguments
    ///
    /// * `host` - The host for resolving source locations
    ///
    /// # Note
    ///
    /// This method may be expensive and should typically only be called in error paths.
    fn resolve_source(
        &self,
        host: &impl BaseHost,
    ) -> Option<(SourceSpan, Option<Arc<SourceFile>>)> {
        let _ = host; // Suppress unused parameter warning for default impl
        self.label_and_source_file()
    }

    /// Returns the clock cycle associated with this error context.
    ///
    /// This is always cheap to access.
    fn clk(&self) -> RowIndex;

    /// Wraps an operation error with context information to create an execution error.
    ///
    /// Creates `ExecutionError::OperationError` when context is available, or
    /// `ExecutionError::OperationErrorNoContext` when context is missing.
    ///
    /// This method uses `label_and_source_file()` for backwards compatibility.
    /// For new lazy implementations, use `wrap_op_err_with_host()` instead.
    fn wrap_op_err(&self, err: OperationError) -> ExecutionError {
        match self.label_and_source_file() {
            Some((label, source_file)) => ExecutionError::OperationError {
                clk: self.clk(),
                label,
                source_file,
                err: Box::new(err),
            },
            None => ExecutionError::OperationErrorNoContext { clk: self.clk(), err: Box::new(err) },
        }
    }

    /// Wraps an operation error with context information, using host for resolution.
    ///
    /// This is the preferred method for lazy error contexts that defer source resolution
    /// until the error path. Creates `ExecutionError::OperationError` when context is
    /// available, or `ExecutionError::OperationErrorNoContext` when context is missing.
    ///
    /// # Arguments
    ///
    /// * `host` - The host for resolving source locations
    /// * `err` - The operation error to wrap
    fn wrap_op_err_with_host(&self, host: &impl BaseHost, err: OperationError) -> ExecutionError {
        match self.resolve_source(host) {
            Some((label, source_file)) => ExecutionError::OperationError {
                clk: self.clk(),
                label,
                source_file,
                err: Box::new(err),
            },
            None => ExecutionError::OperationErrorNoContext { clk: self.clk(), err: Box::new(err) },
        }
    }
}

/// Context information to be used when reporting errors.
pub struct ErrorContextImpl {
    label: SourceSpan,
    source_file: Option<Arc<SourceFile>>,
    clk: RowIndex,
}

impl ErrorContextImpl {
    #[allow(dead_code)]
    pub fn new(
        mast_forest: &MastForest,
        node: &impl MastNodeErrorContext,
        host: &impl BaseHost,
        clk: RowIndex,
    ) -> Self {
        let (label, source_file) =
            Self::precalc_label_and_source_file(None, mast_forest, node, host);
        Self { label, source_file, clk }
    }

    #[allow(dead_code)]
    pub fn new_with_op_idx(
        mast_forest: &MastForest,
        node: &impl MastNodeErrorContext,
        host: &impl BaseHost,
        op_idx: usize,
        clk: RowIndex,
    ) -> Self {
        let op_idx = op_idx.into();
        let (label, source_file) =
            Self::precalc_label_and_source_file(op_idx, mast_forest, node, host);
        Self { label, source_file, clk }
    }

    fn precalc_label_and_source_file(
        op_idx: Option<usize>,
        mast_forest: &MastForest,
        node: &impl MastNodeErrorContext,
        host: &impl BaseHost,
    ) -> (SourceSpan, Option<Arc<SourceFile>>) {
        node.get_assembly_op(mast_forest, op_idx)
            .and_then(|assembly_op| assembly_op.location())
            .map_or_else(
                || (SourceSpan::UNKNOWN, None),
                |location| host.get_label_and_source_file(location),
            )
    }
}

impl ErrorContext for ErrorContextImpl {
    fn label_and_source_file(&self) -> Option<(SourceSpan, Option<Arc<SourceFile>>)> {
        if self.label == SourceSpan::UNKNOWN {
            None
        } else {
            Some((self.label, self.source_file.clone()))
        }
    }

    fn clk(&self) -> RowIndex {
        self.clk
    }
}

impl ErrorContext for () {
    fn label_and_source_file(&self) -> Option<(SourceSpan, Option<Arc<SourceFile>>)> {
        None
    }

    fn clk(&self) -> RowIndex {
        RowIndex::from(0)
    }
}

// LAZY ERROR CONTEXT
// ================================================================================================

/// Lightweight error context handle for lazy source location resolution.
///
/// Unlike [`ErrorContextImpl`] which eagerly pre-computes source information, this struct
/// stores only references and scalars needed to resolve error context later (in the error path).
/// This avoids the cost of MAST traversal and host lookups on the hot success path.
///
/// # Performance
///
/// - **Construction**: Nearly free - just stores pointers and scalars (no MAST walk, no host calls)
/// - **Resolution**: Only happens inside `.map_err()` closure when error actually occurs
///
/// # Feature Flags
///
/// When `no_err_ctx` is enabled, this struct collapses to just the clock cycle, making
/// error context completely zero-cost.
///
/// # Examples
///
/// ```ignore
/// use miden_processor::{OpErrorContext, ResultOpErrExt};
///
/// // Node-level error (no specific operation)
/// let ctx = OpErrorContext::new(program, node_id, clk);
/// some_operation()
///     .map_exec_err(&ctx)?;
///
/// // Operation-level error (specific op index)
/// let ctx = OpErrorContext::with_op(program, node_id, op_idx, clk);
/// execute_operation()
///     .map_exec_err(&ctx)?;
/// ```
#[cfg(not(feature = "no_err_ctx"))]
pub struct OpErrorContext<'a> {
    clk: RowIndex,
    program: &'a MastForest,
    node_id: MastNodeId,
    op_idx: Option<usize>,
}

#[cfg(feature = "no_err_ctx")]
pub struct OpErrorContext<'a> {
    clk: RowIndex,
    _phantom: core::marker::PhantomData<&'a ()>,
}

impl<'a> OpErrorContext<'a> {
    /// Create context for node-level errors (no specific operation index).
    ///
    /// Use this for errors that occur at the node boundary (e.g., node not found,
    /// invalid node type) rather than during execution of a specific operation.
    ///
    /// # Arguments
    ///
    /// * `program` - The MAST forest containing the node
    /// * `node_id` - ID of the node where the error occurred
    /// * `clk` - Clock cycle when the error occurred
    ///
    /// # Performance
    ///
    /// This is a cheap operation - just stores references and scalars. No MAST traversal
    /// or host lookups occur until `label_and_source_file()` is called (in error path).
    #[inline]
    pub fn new(program: &'a MastForest, node_id: MastNodeId, clk: RowIndex) -> Self {
        #[cfg(not(feature = "no_err_ctx"))]
        {
            Self { clk, program, node_id, op_idx: None }
        }

        #[cfg(feature = "no_err_ctx")]
        {
            Self { clk, _phantom: core::marker::PhantomData }
        }
    }

    /// Create context for operation-level errors (specific operation in node).
    ///
    /// Use this for errors that occur during execution of a specific operation
    /// within a node (e.g., divide by zero, failed assertion).
    ///
    /// # Arguments
    ///
    /// * `program` - The MAST forest containing the node
    /// * `node_id` - ID of the node containing the operation
    /// * `op_idx` - Index of the operation within the node
    /// * `clk` - Clock cycle when the error occurred
    ///
    /// # Performance
    ///
    /// This is a cheap operation - just stores references and scalars. No MAST traversal
    /// or host lookups occur until `label_and_source_file()` is called (in error path).
    #[inline]
    pub fn with_op(
        program: &'a MastForest,
        node_id: MastNodeId,
        op_idx: usize,
        clk: RowIndex,
    ) -> Self {
        #[cfg(not(feature = "no_err_ctx"))]
        {
            Self {
                clk,
                program,
                node_id,
                op_idx: Some(op_idx),
            }
        }

        #[cfg(feature = "no_err_ctx")]
        {
            Self { clk, _phantom: core::marker::PhantomData }
        }
    }
}

#[cfg(not(feature = "no_err_ctx"))]
impl<'a> ErrorContext for OpErrorContext<'a> {
    #[inline]
    fn clk(&self) -> RowIndex {
        self.clk
    }

    fn label_and_source_file(&self) -> Option<(SourceSpan, Option<Arc<SourceFile>>)> {
        // For backwards compatibility, but this won't have full source resolution.
        // Callers should use resolve_source() with a host instead.
        use miden_core::mast::MastNode;

        let node = self.program.get_node_by_id(self.node_id)?;

        if let Some(op_idx) = self.op_idx {
            // Operation-level error: get specific operation's location
            // Need to dispatch through the enum to access MastNodeErrorContext methods
            let assembly_op = match node {
                MastNode::Block(n) => n.get_assembly_op(self.program, Some(op_idx)),
                MastNode::Join(n) => n.get_assembly_op(self.program, Some(op_idx)),
                MastNode::Split(n) => n.get_assembly_op(self.program, Some(op_idx)),
                MastNode::Loop(n) => n.get_assembly_op(self.program, Some(op_idx)),
                MastNode::Call(n) => n.get_assembly_op(self.program, Some(op_idx)),
                MastNode::Dyn(n) => n.get_assembly_op(self.program, Some(op_idx)),
                MastNode::External(n) => n.get_assembly_op(self.program, Some(op_idx)),
            }?;
            let _location = assembly_op.location()?;
            // Without host, we can't fully resolve - just return UNKNOWN span
            // Callers should use resolve_source() with a host for full resolution
            Some((SourceSpan::UNKNOWN, None))
        } else {
            // Node-level error: no operation-specific location available
            None
        }
    }

    fn resolve_source(
        &self,
        host: &impl BaseHost,
    ) -> Option<(SourceSpan, Option<Arc<SourceFile>>)> {
        // Expensive work happens here, but only in error path.
        // This defers MAST traversal and host lookups until we actually need the error.
        use miden_core::mast::MastNode;

        let node = self.program.get_node_by_id(self.node_id)?;

        // Try to get assembly op location - use op_idx if available, otherwise try None
        // (node-level)
        let assembly_op = match node {
            MastNode::Block(n) => n.get_assembly_op(self.program, self.op_idx),
            MastNode::Join(n) => n.get_assembly_op(self.program, self.op_idx),
            MastNode::Split(n) => n.get_assembly_op(self.program, self.op_idx),
            MastNode::Loop(n) => n.get_assembly_op(self.program, self.op_idx),
            MastNode::Call(n) => n.get_assembly_op(self.program, self.op_idx),
            MastNode::Dyn(n) => n.get_assembly_op(self.program, self.op_idx),
            MastNode::External(n) => n.get_assembly_op(self.program, self.op_idx),
        }?;

        let location = assembly_op.location()?;
        // Now we can properly resolve the label and source file via the host
        let (label, source_file) = host.get_label_and_source_file(location);

        // If the span is unknown/default and there's no source file, treat as unavailable
        if label == SourceSpan::default() && source_file.is_none() {
            return None;
        }

        Some((label, source_file))
    }
}

#[cfg(feature = "no_err_ctx")]
impl<'a> ErrorContext for OpErrorContext<'a> {
    #[inline]
    fn clk(&self) -> RowIndex {
        self.clk
    }

    #[inline]
    fn label_and_source_file(&self) -> Option<(SourceSpan, Option<Arc<SourceFile>>)> {
        None // Always no context in no_err_ctx build
    }

    #[inline]
    fn resolve_source(
        &self,
        _host: &impl BaseHost,
    ) -> Option<(SourceSpan, Option<Arc<SourceFile>>)> {
        None // Always no context in no_err_ctx build
    }
}

// RESULT EXTENSION
// ================================================================================================

/// Extension trait for `Result<T, OperationError>` to simplify conversion to `ExecutionError`.
///
/// This trait provides convenient methods to wrap `OperationError` in `ExecutionError` using
/// either explicit context information or error context providers.
pub trait ResultOpErrExt<T> {
    /// Converts `Result<T, OperationError>` to `Result<T, ExecutionError>` by wrapping the error
    /// in `ExecutionError::OperationErrorNoContext` with the given clock cycle.
    ///
    /// Use this when error context is not available (e.g., loading external MAST forests).
    ///
    /// # Example
    /// ```ignore
    /// program.get_node_by_id(node_id)
    ///     .ok_or(OperationError::MastNodeNotFoundInForest { node_id })
    ///     .map_exec_err_no_ctx(self.system.clk())?;
    /// ```
    fn map_exec_err_no_ctx(self, clk: RowIndex) -> Result<T, ExecutionError>;

    /// Converts `Result<T, OperationError>` to `Result<T, ExecutionError>` by wrapping the error
    /// using the provided error context.
    ///
    /// This automatically attaches source location information when available.
    ///
    /// # Example
    /// ```ignore
    /// program.get_node_by_id(node_id)
    ///     .ok_or(OperationError::MastNodeNotFoundInForest { node_id })
    ///     .map_exec_err(&err_ctx)?;
    /// ```
    fn map_exec_err(self, err_ctx: &impl ErrorContext) -> Result<T, ExecutionError>;

    /// Converts `Result<T, OperationError>` to `Result<T, ExecutionError>` by wrapping the error
    /// using the provided error context and host.
    ///
    /// This is the preferred method for lazy error contexts (like [`OpErrorContext`]) that defer
    /// source resolution until the error path. It enables full source location resolution including
    /// source file information.
    ///
    /// # Arguments
    ///
    /// * `err_ctx` - Error context handle (cheap to construct)
    /// * `host` - Host for resolving source locations (only used in error path)
    ///
    /// # Example
    /// ```ignore
    /// let ctx = OpErrorContext::with_op(program, node_id, op_idx, clk);
    /// some_operation()
    ///     .map_exec_err_with_host(&ctx, host)?;
    /// ```
    fn map_exec_err_with_host(
        self,
        err_ctx: &impl ErrorContext,
        host: &impl BaseHost,
    ) -> Result<T, ExecutionError>;
}

impl<T> ResultOpErrExt<T> for Result<T, OperationError> {
    #[inline]
    fn map_exec_err_no_ctx(self, clk: RowIndex) -> Result<T, ExecutionError> {
        self.map_err(|err| ExecutionError::OperationErrorNoContext { clk, err: Box::new(err) })
    }

    #[inline]
    fn map_exec_err(self, err_ctx: &impl ErrorContext) -> Result<T, ExecutionError> {
        self.map_err(|err| err_ctx.wrap_op_err(err))
    }

    #[inline]
    fn map_exec_err_with_host(
        self,
        err_ctx: &impl ErrorContext,
        host: &impl BaseHost,
    ) -> Result<T, ExecutionError> {
        self.map_err(|err| err_ctx.wrap_op_err_with_host(host, err))
    }
}

impl<T> ResultOpErrExt<T> for OperationError {
    #[inline]
    fn map_exec_err_no_ctx(self, clk: RowIndex) -> Result<T, ExecutionError> {
        Err(ExecutionError::OperationErrorNoContext { clk, err: Box::new(self) })
    }

    #[inline]
    fn map_exec_err(self, err_ctx: &impl ErrorContext) -> Result<T, ExecutionError> {
        Err(err_ctx.wrap_op_err(self))
    }

    #[inline]
    fn map_exec_err_with_host(
        self,
        err_ctx: &impl ErrorContext,
        host: &impl BaseHost,
    ) -> Result<T, ExecutionError> {
        Err(err_ctx.wrap_op_err_with_host(host, self))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod error_assertions {
    use super::*;

    /// Asserts at compile time that the passed error has Send + Sync + 'static bounds.
    fn _assert_error_is_send_sync_static<E: core::error::Error + Send + Sync + 'static>(_: E) {}

    fn _assert_execution_error_bounds(err: ExecutionError) {
        _assert_error_is_send_sync_static(err);
    }
}
