// Allow unused assignments - required by miette::Diagnostic derive macro
#![allow(unused_assignments)]

use alloc::{boxed::Box, string::String, sync::Arc, vec::Vec};

use miden_core::{deferred::PrecompileError, program::MIN_STACK_DEPTH};
use miden_debug_types::{Location, SourceFile, SourceSpan};
use miden_mast_package::debug_info::{DebugSourceNodeId, PackageDebugInfo};
use miden_utils_diagnostics::{Diagnostic, miette};

use crate::{
    BaseHost, ContextId, Felt, Word,
    advice::AdviceError,
    event::{EventError, EventId, EventName},
    fast::SystemEventError,
    utils::to_hex,
};

// EXECUTION ERROR
// ================================================================================================

#[derive(Debug, thiserror::Error, Diagnostic)]
pub enum ExecutionError {
    #[error("failed to execute arithmetic circuit evaluation operation: {error}")]
    #[diagnostic()]
    AceChipError {
        #[label("this call failed")]
        label: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
        error: AceError,
    },
    #[error("{err}")]
    #[diagnostic(forward(err))]
    AdviceError {
        #[label]
        label: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
        err: AdviceError,
    },
    #[error("exceeded the allowed number of max cycles {0}")]
    CycleLimitExceeded(u32),
    #[error("error during processing of event {}", match event_name {
        Some(name) => format!("'{name}' (ID: {event_id})"),
        None => format!("with ID: {event_id}"),
    })]
    #[diagnostic()]
    EventError {
        #[label]
        label: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
        event_id: EventId,
        event_name: Option<EventName>,
        #[source]
        error: EventError,
    },
    /// Deferred system event failed while validating or evaluating a committed node.
    #[error("{err}")]
    #[diagnostic()]
    DeferredError {
        #[label]
        label: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
        err: PrecompileError,
    },
    #[error("failed to execute the program for internal reason: {0}")]
    Internal(&'static str),
    #[error("operand stack depth {depth} exceeds the maximum of {max}")]
    StackDepthLimitExceeded { depth: usize, max: usize },
    /// This means trace generation would go over the configured row limit.
    ///
    /// In parallel trace building, this is used for core-row prechecks and chiplet overflow.
    #[error("trace length exceeded the maximum of {0} rows")]
    TraceLenExceeded(usize),
    /// Memory error with source context for diagnostics.
    ///
    /// Use `MemoryResultExt::map_mem_err` to convert `Result<T, MemoryError>` with context.
    #[error("{err}")]
    #[diagnostic(forward(err))]
    MemoryError {
        #[label]
        label: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
        err: MemoryError,
    },
    /// Memory error without source context (for internal operations like FMP initialization).
    ///
    /// Use `ExecutionError::MemoryErrorNoCtx` for memory errors that don't have error context
    /// available (e.g., during call/syscall context initialization).
    #[error(transparent)]
    #[diagnostic(transparent)]
    MemoryErrorNoCtx(MemoryError),
    #[error("{err}")]
    #[diagnostic(forward(err))]
    OperationError {
        #[label]
        label: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
        err: OperationError,
    },
    #[error("stack should have at most {MIN_STACK_DEPTH} elements at the end of program execution, but had {} elements", MIN_STACK_DEPTH + .0)]
    OutputStackOverflow(usize),
    #[error("procedure with root digest {root_digest} could not be found")]
    #[diagnostic()]
    ProcedureNotFound {
        #[label]
        label: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
        root_digest: Word,
    },
    #[error("failed to generate STARK proof: {0}")]
    ProvingError(String),
    #[error(transparent)]
    HostError(#[from] HostError),
}

impl ExecutionError {
    /// Wraps an advice error without source-location context.
    pub fn advice_error_no_context(err: AdviceError) -> Self {
        Self::AdviceError {
            label: SourceSpan::UNKNOWN,
            source_file: None,
            err,
        }
    }

    /// Wraps a deferred error without source-location context.
    pub fn deferred_error_no_context(err: PrecompileError) -> Self {
        Self::DeferredError {
            label: SourceSpan::UNKNOWN,
            source_file: None,
            err,
        }
    }
}

impl AsRef<dyn Diagnostic> for ExecutionError {
    fn as_ref(&self) -> &(dyn Diagnostic + 'static) {
        self
    }
}

// ACE ERROR
// ================================================================================================

#[derive(Debug, thiserror::Error)]
#[error("ace circuit evaluation failed: {0}")]
pub struct AceError(pub String);

// ACE EVAL ERROR
// ================================================================================================

/// Context-free error type for ACE circuit evaluation operations.
///
/// This enum wraps errors from ACE evaluation and memory subsystems without
/// carrying source location context. Context is added at the call site via
/// `AceEvalResultExt::map_ace_eval_err`.
#[derive(Debug, thiserror::Error)]
pub enum AceEvalError {
    #[error(transparent)]
    Ace(#[from] AceError),
    #[error(transparent)]
    Memory(#[from] MemoryError),
}

// HOST ERROR
// ================================================================================================

/// Error type for host-related operations.
#[derive(Debug, thiserror::Error)]
pub enum HostError {
    #[error("attempted to add event handler for '{event}' (already registered)")]
    DuplicateEventHandler { event: EventName },
    #[error("attempted to add event handler for '{event}' (reserved system event)")]
    ReservedEventNamespace { event: EventName },
}

// IO ERROR
// ================================================================================================

/// Context-free error type for IO operations.
///
/// This enum wraps errors from the advice provider and memory subsystems without
/// carrying source location context. Context is added at the call site via
/// `IoResultExt::map_io_err`.
#[derive(Debug, thiserror::Error, Diagnostic)]
pub enum IoError {
    #[error(transparent)]
    Advice(#[from] AdviceError),
    #[error(transparent)]
    Memory(#[from] MemoryError),
    #[error(transparent)]
    #[diagnostic(transparent)]
    Operation(#[from] OperationError),
    /// Stack operation error (increment/decrement size failures).
    ///
    /// These are internal execution errors that don't need additional context
    /// since they already carry their own error information.
    #[error(transparent)]
    #[diagnostic(transparent)]
    Execution(Box<ExecutionError>),
}

impl From<ExecutionError> for IoError {
    fn from(err: ExecutionError) -> Self {
        IoError::Execution(Box::new(err))
    }
}

// MEMORY ERROR
// ================================================================================================

/// Lightweight error type for memory operations.
///
/// This enum captures error conditions without expensive context information (no source location,
/// no file references). When a `MemoryError` propagates up to become an `ExecutionError`, the
/// context is resolved lazily via `MapExecErr::map_exec_err`.
#[derive(Debug, thiserror::Error, Diagnostic)]
pub enum MemoryError {
    #[error("memory address cannot exceed 2^32 but was {addr}")]
    AddressOutOfBounds { addr: u64 },
    #[error(
        "memory address {addr} in context {ctx} was read and written, or written twice, in the same clock cycle {clk}"
    )]
    IllegalMemoryAccess { ctx: ContextId, addr: u32, clk: Felt },
    #[error(
        "memory range start address cannot exceed end address, but was ({start_addr}, {end_addr})"
    )]
    InvalidMemoryRange { start_addr: u64, end_addr: u64 },
    #[error(
        "word access at memory address {addr} in context {ctx} is unaligned: word accesses require addresses that are multiples of 4"
    )]
    UnalignedWordAccess { addr: u32, ctx: ContextId },
    #[error("failed to read from memory: {0}")]
    MemoryReadFailed(String),
    #[error(
        "writing to memory address {addr} in context {ctx} would exceed the maximum number of memory elements {max}"
    )]
    #[diagnostic(help(
        "increase the limit via `ExecutionOptions::with_max_memory_elements`, or reduce the number of distinct memory addresses the program writes to"
    ))]
    MemoryElementLimitExceeded { ctx: ContextId, addr: u32, max: usize },
}

// CRYPTO ERROR
// ================================================================================================

/// Context-free error type for cryptographic operations (Merkle path verification, updates).
///
/// This enum wraps errors from the advice provider and operation subsystems without carrying
/// source location context. Context is added at the call site via
/// `CryptoResultExt::map_crypto_err`.
#[derive(Debug, thiserror::Error, Diagnostic)]
pub enum CryptoError {
    #[error(transparent)]
    Advice(#[from] AdviceError),
    #[error(transparent)]
    #[diagnostic(transparent)]
    Operation(#[from] OperationError),
}

// OPERATION ERROR
// ================================================================================================

/// Lightweight error type for operations that can fail.
///
/// This enum captures error conditions without expensive context information (no source location,
/// no file references). When an `OperationError` propagates up to become an `ExecutionError`, the
/// context is resolved lazily via extension traits like `OperationResultExt::map_exec_err`.
///
/// # Adding new errors (for contributors)
///
/// **Use `OperationError` when:**
/// - The error occurs during operation execution (e.g., assertion failures, type mismatches)
/// - Context can be resolved at the call site via the extension traits
/// - The error needs both a human-readable message and optional diagnostic help
///
/// **Avoid duplicating error context.** Context is added by the extension traits,
/// so do NOT add `label` or `source_file` fields to the variant.
///
/// **Pattern at call sites:**
/// ```ignore
/// // Return OperationError and let the caller wrap it:
/// fn some_op() -> Result<(), OperationError> {
///     Err(OperationError::DivideByZero)
/// }
///
/// // Caller wraps with context lazily:
/// some_op().map_exec_err()?;
/// ```
///
/// For wrapper errors (`AdviceError`, `EventError`, `AceError`), use the corresponding extension
/// traits (`AdviceResultExt`, `AceResultExt`) or helper functions (`advice_error_with_context`,
/// `event_error_with_context`).
#[derive(Debug, Clone, thiserror::Error, Diagnostic)]
pub enum OperationError {
    #[error("external node with mast root {0} resolved to an external node")]
    CircularExternalNode(Word),
    #[error("division by zero: divisor must be non-zero for division or modulo operations")]
    DivideByZero,
    #[error(
        "assertion failed with error {}",
        match err_msg {
            Some(msg) => format!("message: {msg}"),
            None => format!("code: {err_code}"),
        }
    )]
    FailedAssertion {
        err_code: Felt,
        err_msg: Option<Arc<str>>,
    },
    #[error(
        "u32 assertion failed: u32assert2 requires both stack values to be valid 32-bit unsigned integers; error {}; invalid values: {invalid_values:?}",
        match err_msg {
            Some(msg) => format!("message: {msg}"),
            None => format!("code: {err_code}"),
        }
    )]
    U32AssertionFailed {
        err_code: Felt,
        err_msg: Option<Arc<str>>,
        invalid_values: Vec<Felt>,
    },
    #[error("FRI operation failed: {0}")]
    FriError(String),
    #[error(
        "invalid crypto operation: Merkle path length {path_len} does not match expected depth {depth}"
    )]
    InvalidMerklePathLength { path_len: usize, depth: Felt },
    #[error("when returning from a call, stack depth must be {MIN_STACK_DEPTH}, but was {depth}")]
    InvalidStackDepthOnReturn { depth: usize },
    #[error("ilog2 requires a non-zero argument")]
    LogArgumentZero,
    #[error(
        "MAST forest in host indexed by procedure root {root_digest} doesn't contain that root"
    )]
    MalformedMastForestInHost { root_digest: Word },
    #[error("merkle path verification failed for value {value} at index {index} in the Merkle tree with root {root} (error {err})",
      value = to_hex(inner.value.as_bytes()),
      root = to_hex(inner.root.as_bytes()),
      index = inner.index,
      err = match &inner.err_msg {
        Some(msg) => format!("message: {msg}"),
        None => format!("code: {}", inner.err_code),
      }
    )]
    MerklePathVerificationFailed {
        inner: Box<MerklePathVerificationFailedInner>,
    },
    #[error("{message}, but got {value}", message = context.message())]
    NotBinaryValue {
        context: BinaryValueErrorContext,
        value: Felt,
    },
    #[error("operation expected u32 values, but got values: {values:?}")]
    NotU32Values { values: Vec<Felt> },
    #[error("syscall failed: procedure with root {proc_root} was not found in the kernel")]
    SyscallTargetNotInKernel { proc_root: Word },
    #[error("failed to execute the operation for internal reason: {0}")]
    Internal(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryValueErrorContext {
    Operation,
    If,
    Loop,
}

impl BinaryValueErrorContext {
    const fn message(self) -> &'static str {
        match self {
            Self::Operation => "operation expected a binary value",
            Self::If => "if statement expected a binary value on top of the stack",
            Self::Loop => {
                "loop condition must be a binary value on entry and each subsequent iteration"
            },
        }
    }
}

impl OperationError {
    /// Wraps this error with execution context to produce an `ExecutionError`.
    ///
    /// This is useful when working with `ControlFlow` or other non-`Result` return types
    /// where the `OperationResultExt::map_exec_err` extension trait cannot be used directly.
    pub fn with_context(self) -> ExecutionError {
        let (label, source_file) = get_label_and_source_file();
        ExecutionError::OperationError { label, source_file, err: self }
    }

    /// Wraps this error with package-owned source-occurrence execution context.
    ///
    /// Unlike [`Self::with_context`], this resolves source metadata from package debug sections
    /// keyed by a source/debug MAST occurrence rather than by the reduced execution MAST node.
    pub fn with_package_source_context(
        self,
        context: PackageSourceDebugContext<'_>,
        host: &impl BaseHost,
        op_idx: Option<usize>,
    ) -> ExecutionError {
        let (label, source_file) =
            label_and_source_file_from_location(context.assembly_location(op_idx), host);
        ExecutionError::OperationError {
            label,
            source_file,
            err: self.with_package_debug_info(context.debug_info()),
        }
    }

    fn with_package_debug_info(self, debug_info: &PackageDebugInfo) -> Self {
        match self {
            Self::FailedAssertion { err_code, err_msg: None } => Self::FailedAssertion {
                err_msg: debug_info.error_message(err_code.as_canonical_u64()),
                err_code,
            },
            Self::U32AssertionFailed { err_code, err_msg: None, invalid_values } => {
                Self::U32AssertionFailed {
                    err_msg: debug_info.error_message(err_code.as_canonical_u64()),
                    err_code,
                    invalid_values,
                }
            },
            Self::MerklePathVerificationFailed { mut inner } if inner.err_msg.is_none() => {
                inner.err_msg = debug_info.error_message(inner.err_code.as_canonical_u64());
                Self::MerklePathVerificationFailed { inner }
            },
            err => err,
        }
    }
}

/// Inner data for `OperationError::MerklePathVerificationFailed`.
///
/// Boxed to reduce the size of `OperationError`.
#[derive(Debug, Clone)]
pub struct MerklePathVerificationFailedInner {
    pub value: Word,
    pub index: Felt,
    pub root: Word,
    pub err_code: Felt,
    pub err_msg: Option<Arc<str>>,
}

// EXTENSION TRAITS
// ================================================================================================

/// Source-occurrence debug context decoded from package debug sections.
///
/// This keeps diagnostic lookup keyed by [`DebugSourceNodeId`] so two source occurrences that
/// reduce to the same executable MAST node can still report distinct source locations.
#[derive(Clone, Copy, Debug)]
pub struct PackageSourceDebugContext<'a> {
    debug_info: &'a PackageDebugInfo,
    source_node_id: Option<DebugSourceNodeId>,
}

impl<'a> PackageSourceDebugContext<'a> {
    /// Creates a source debug context for one package-owned source/debug MAST occurrence.
    pub fn new(debug_info: &'a PackageDebugInfo, source_node_id: DebugSourceNodeId) -> Self {
        Self {
            debug_info,
            source_node_id: Some(source_node_id),
        }
    }

    /// Creates a package debug context when source location metadata may be unavailable.
    pub(crate) fn new_optional(
        debug_info: &'a PackageDebugInfo,
        source_node_id: Option<DebugSourceNodeId>,
    ) -> Self {
        Self { debug_info, source_node_id }
    }

    /// Returns the source/debug MAST occurrence associated with this context, if known.
    pub fn source_node_id(&self) -> Option<DebugSourceNodeId> {
        self.source_node_id
    }

    /// Returns the package debug info backing this context.
    pub fn debug_info(&self) -> &'a PackageDebugInfo {
        self.debug_info
    }

    /// Returns source location metadata for `op_idx`, if present.
    ///
    /// If `op_idx` is absent, this falls back to the first operation row for the source occurrence.
    pub fn assembly_location(&self, op_idx: Option<usize>) -> Option<&'a Location> {
        let source_node_id = self.source_node_id?;
        let assembly_op = match op_idx {
            Some(op_idx) => u32::try_from(op_idx)
                .ok()
                .and_then(|op_idx| self.debug_info.asm_op_for_operation(source_node_id, op_idx)),
            None => self.debug_info.first_asm_op_for_source_node(source_node_id),
        }?;

        assembly_op.location.as_ref()
    }
}

fn label_and_source_file_from_location(
    location: Option<&Location>,
    host: &impl BaseHost,
) -> (SourceSpan, Option<Arc<SourceFile>>) {
    location.map_or_else(
        || (SourceSpan::UNKNOWN, None),
        |location| host.get_label_and_source_file(location),
    )
}

/// Computes the label and source file for error context.
///
/// This function is called by the extension traits to compute source location
/// only when an error occurs. Since errors are rare, the cost of source metadata lookup is
/// acceptable.
fn get_label_and_source_file() -> (SourceSpan, Option<Arc<SourceFile>>) {
    (SourceSpan::UNKNOWN, None)
}

/// Wraps an `AdviceError` with execution context to produce an `ExecutionError`.
///
/// This is useful when working with `ControlFlow` or other non-`Result` return types
/// where the extension traits cannot be used directly.
pub fn advice_error_with_context(err: AdviceError) -> ExecutionError {
    let (label, source_file) = get_label_and_source_file();
    ExecutionError::AdviceError { label, source_file, err }
}

/// Wraps an `AdviceError` with package-owned source-occurrence execution context.
pub fn advice_error_with_package_source_context(
    err: AdviceError,
    context: PackageSourceDebugContext<'_>,
    host: &impl BaseHost,
    op_idx: Option<usize>,
) -> ExecutionError {
    let (label, source_file) =
        label_and_source_file_from_location(context.assembly_location(op_idx), host);
    ExecutionError::AdviceError { label, source_file, err }
}

/// Wraps an `EventError` with execution context to produce an `ExecutionError`.
///
/// This is useful when working with `ControlFlow` or other non-`Result` return types
/// where an extension trait on `Result` cannot be used directly.
pub fn event_error_with_context(
    error: EventError,
    event_id: EventId,
    event_name: Option<EventName>,
) -> ExecutionError {
    let (label, source_file) = get_label_and_source_file();
    ExecutionError::EventError {
        label,
        source_file,
        event_id,
        event_name,
        error,
    }
}

/// Wraps an `EventError` with package-owned source-occurrence execution context.
pub fn event_error_with_package_source_context(
    error: EventError,
    context: PackageSourceDebugContext<'_>,
    host: &impl BaseHost,
    op_idx: Option<usize>,
    event_id: EventId,
    event_name: Option<EventName>,
) -> ExecutionError {
    let (label, source_file) =
        label_and_source_file_from_location(context.assembly_location(op_idx), host);
    ExecutionError::EventError {
        label,
        source_file,
        event_id,
        event_name,
        error,
    }
}

/// Creates a `ProcedureNotFound` error with execution context.
pub fn procedure_not_found_with_context(root_digest: Word) -> ExecutionError {
    let (label, source_file) = get_label_and_source_file();
    ExecutionError::ProcedureNotFound { label, source_file, root_digest }
}

/// Creates a `ProcedureNotFound` error with package-owned source-occurrence execution context.
pub fn procedure_not_found_with_package_source_context(
    root_digest: Word,
    context: PackageSourceDebugContext<'_>,
    host: &impl BaseHost,
) -> ExecutionError {
    let (label, source_file) =
        label_and_source_file_from_location(context.assembly_location(None), host);
    ExecutionError::ProcedureNotFound { label, source_file, root_digest }
}

/// Creates a `MalformedMastForestInHost` operation error with execution context.
pub fn malformed_mast_forest_with_context(
    root_digest: Word,
    context: Option<PackageSourceDebugContext<'_>>,
    host: &impl BaseHost,
) -> ExecutionError {
    let err = OperationError::MalformedMastForestInHost { root_digest };
    match context {
        Some(context) => err.with_package_source_context(context, host, None),
        None => err.with_context(),
    }
}

// CONSOLIDATED EXTENSION TRAITS (plafer's approach)
// ================================================================================================
//
// Three traits organized by method signature rather than by error type:
// 1. MapExecErr - for errors with basic context
// 2. MapExecErrWithOpIdx - for errors in basic blocks that may need op_idx
// 3. MapExecErrNoCtx - for errors without any context

/// Extension trait for mapping errors to `ExecutionError`.
///
/// Legacy MAST-local debug metadata no longer provides source locations here; callers that have
/// package-owned source context should use `map_exec_err_with_package_source_op_idx`.
pub trait MapExecErr<T> {
    fn map_exec_err(self) -> Result<T, ExecutionError>;
}

/// Extension trait for mapping errors to `ExecutionError` with op index context.
///
/// Implement this for error types that occur within basic blocks where the
/// operation index is available for more precise source location.
pub trait MapExecErrWithOpIdx<T> {
    fn map_exec_err_with_op_idx(self) -> Result<T, ExecutionError>;

    fn map_exec_err_with_package_source_op_idx(
        self,
        context: Option<PackageSourceDebugContext<'_>>,
        _host: &impl BaseHost,
        _op_idx: usize,
    ) -> Result<T, ExecutionError>
    where
        Self: Sized,
    {
        if context.is_some() {
            return Err(ExecutionError::Internal(
                "package source context is unsupported for this error type",
            ));
        }

        self.map_exec_err_with_op_idx()
    }
}

/// Extension trait for mapping errors to `ExecutionError` without context.
///
/// Implement this for error types that may need to be converted when no
/// error context is available (e.g., during initialization).
pub trait MapExecErrNoCtx<T> {
    fn map_exec_err_no_ctx(self) -> Result<T, ExecutionError>;
}

// OperationError implementations
impl<T> MapExecErr<T> for Result<T, OperationError> {
    #[inline(always)]
    fn map_exec_err(self) -> Result<T, ExecutionError> {
        match self {
            Ok(v) => Ok(v),
            Err(err) => {
                let (label, source_file) = get_label_and_source_file();
                Err(ExecutionError::OperationError { label, source_file, err })
            },
        }
    }
}

impl<T> MapExecErrWithOpIdx<T> for Result<T, OperationError> {
    #[inline(always)]
    fn map_exec_err_with_op_idx(self) -> Result<T, ExecutionError> {
        match self {
            Ok(v) => Ok(v),
            Err(err) => {
                let (label, source_file) = get_label_and_source_file();
                Err(ExecutionError::OperationError { label, source_file, err })
            },
        }
    }

    #[inline(always)]
    fn map_exec_err_with_package_source_op_idx(
        self,
        context: Option<PackageSourceDebugContext<'_>>,
        host: &impl BaseHost,
        op_idx: usize,
    ) -> Result<T, ExecutionError> {
        match (self, context) {
            (Ok(v), _) => Ok(v),
            (Err(err), Some(context)) => {
                Err(err.with_package_source_context(context, host, Some(op_idx)))
            },
            (Err(err), None) => {
                let (label, source_file) = get_label_and_source_file();
                Err(ExecutionError::OperationError { label, source_file, err })
            },
        }
    }
}

impl<T> MapExecErrNoCtx<T> for Result<T, OperationError> {
    #[inline(always)]
    fn map_exec_err_no_ctx(self) -> Result<T, ExecutionError> {
        match self {
            Ok(v) => Ok(v),
            Err(err) => Err(ExecutionError::OperationError {
                label: SourceSpan::UNKNOWN,
                source_file: None,
                err,
            }),
        }
    }
}

// AdviceError implementations
impl<T> MapExecErr<T> for Result<T, AdviceError> {
    #[inline(always)]
    fn map_exec_err(self) -> Result<T, ExecutionError> {
        match self {
            Ok(v) => Ok(v),
            Err(err) => Err(advice_error_with_context(err)),
        }
    }
}

impl<T> MapExecErrNoCtx<T> for Result<T, AdviceError> {
    #[inline(always)]
    fn map_exec_err_no_ctx(self) -> Result<T, ExecutionError> {
        match self {
            Ok(v) => Ok(v),
            Err(err) => Err(ExecutionError::AdviceError {
                label: SourceSpan::UNKNOWN,
                source_file: None,
                err,
            }),
        }
    }
}

// MemoryError implementations
impl<T> MapExecErr<T> for Result<T, MemoryError> {
    #[inline(always)]
    fn map_exec_err(self) -> Result<T, ExecutionError> {
        match self {
            Ok(v) => Ok(v),
            Err(err) => {
                let (label, source_file) = get_label_and_source_file();
                Err(ExecutionError::MemoryError { label, source_file, err })
            },
        }
    }
}

impl<T> MapExecErrWithOpIdx<T> for Result<T, MemoryError> {
    #[inline(always)]
    fn map_exec_err_with_op_idx(self) -> Result<T, ExecutionError> {
        match self {
            Ok(v) => Ok(v),
            Err(err) => {
                let (label, source_file) = get_label_and_source_file();
                Err(ExecutionError::MemoryError { label, source_file, err })
            },
        }
    }

    #[inline(always)]
    fn map_exec_err_with_package_source_op_idx(
        self,
        context: Option<PackageSourceDebugContext<'_>>,
        host: &impl BaseHost,
        op_idx: usize,
    ) -> Result<T, ExecutionError> {
        match (self, context) {
            (Ok(v), _) => Ok(v),
            (Err(err), Some(context)) => {
                let (label, source_file) = label_and_source_file_from_location(
                    context.assembly_location(Some(op_idx)),
                    host,
                );
                Err(ExecutionError::MemoryError { label, source_file, err })
            },
            (Err(err), None) => {
                let (label, source_file) = get_label_and_source_file();
                Err(ExecutionError::MemoryError { label, source_file, err })
            },
        }
    }
}

// SystemEventError implementations
impl<T> MapExecErr<T> for Result<T, SystemEventError> {
    #[inline(always)]
    fn map_exec_err(self) -> Result<T, ExecutionError> {
        match self {
            Ok(v) => Ok(v),
            Err(err) => {
                let (label, source_file) = get_label_and_source_file();
                Err(match err {
                    SystemEventError::Advice(err) => {
                        ExecutionError::AdviceError { label, source_file, err }
                    },
                    SystemEventError::Operation(err) => {
                        ExecutionError::OperationError { label, source_file, err }
                    },
                    SystemEventError::Memory(err) => {
                        ExecutionError::MemoryError { label, source_file, err }
                    },
                    SystemEventError::Deferred(err) => {
                        ExecutionError::DeferredError { label, source_file, err }
                    },
                })
            },
        }
    }
}

impl<T> MapExecErrWithOpIdx<T> for Result<T, SystemEventError> {
    #[inline(always)]
    fn map_exec_err_with_op_idx(self) -> Result<T, ExecutionError> {
        match self {
            Ok(v) => Ok(v),
            Err(err) => {
                let (label, source_file) = get_label_and_source_file();
                Err(match err {
                    SystemEventError::Advice(err) => {
                        ExecutionError::AdviceError { label, source_file, err }
                    },
                    SystemEventError::Operation(err) => {
                        ExecutionError::OperationError { label, source_file, err }
                    },
                    SystemEventError::Memory(err) => {
                        ExecutionError::MemoryError { label, source_file, err }
                    },
                    SystemEventError::Deferred(err) => {
                        ExecutionError::DeferredError { label, source_file, err }
                    },
                })
            },
        }
    }

    #[inline(always)]
    fn map_exec_err_with_package_source_op_idx(
        self,
        context: Option<PackageSourceDebugContext<'_>>,
        host: &impl BaseHost,
        op_idx: usize,
    ) -> Result<T, ExecutionError> {
        match (self, context) {
            (Ok(v), _) => Ok(v),
            (Err(err), Some(context)) => {
                let (label, source_file) = label_and_source_file_from_location(
                    context.assembly_location(Some(op_idx)),
                    host,
                );
                Err(match err {
                    SystemEventError::Advice(err) => {
                        ExecutionError::AdviceError { label, source_file, err }
                    },
                    SystemEventError::Operation(err) => {
                        ExecutionError::OperationError { label, source_file, err }
                    },
                    SystemEventError::Memory(err) => {
                        ExecutionError::MemoryError { label, source_file, err }
                    },
                    SystemEventError::Deferred(err) => {
                        ExecutionError::DeferredError { label, source_file, err }
                    },
                })
            },
            (Err(err), None) => {
                let (label, source_file) = get_label_and_source_file();
                Err(match err {
                    SystemEventError::Advice(err) => {
                        ExecutionError::AdviceError { label, source_file, err }
                    },
                    SystemEventError::Operation(err) => {
                        ExecutionError::OperationError { label, source_file, err }
                    },
                    SystemEventError::Memory(err) => {
                        ExecutionError::MemoryError { label, source_file, err }
                    },
                    SystemEventError::Deferred(err) => {
                        ExecutionError::DeferredError { label, source_file, err }
                    },
                })
            },
        }
    }
}

// IoError implementations
impl<T> MapExecErrWithOpIdx<T> for Result<T, IoError> {
    #[inline(always)]
    fn map_exec_err_with_op_idx(self) -> Result<T, ExecutionError> {
        match self {
            Ok(v) => Ok(v),
            Err(err) => {
                let (label, source_file) = get_label_and_source_file();
                Err(match err {
                    IoError::Advice(err) => ExecutionError::AdviceError { label, source_file, err },
                    IoError::Memory(err) => ExecutionError::MemoryError { label, source_file, err },
                    IoError::Operation(err) => {
                        ExecutionError::OperationError { label, source_file, err }
                    },
                    // Execution errors are already fully formed with their own message.
                    IoError::Execution(boxed_err) => *boxed_err,
                })
            },
        }
    }

    #[inline(always)]
    fn map_exec_err_with_package_source_op_idx(
        self,
        context: Option<PackageSourceDebugContext<'_>>,
        host: &impl BaseHost,
        op_idx: usize,
    ) -> Result<T, ExecutionError> {
        match (self, context) {
            (Ok(v), _) => Ok(v),
            (Err(IoError::Execution(boxed_err)), _) => Err(*boxed_err),
            (Err(err), Some(context)) => {
                let (label, source_file) = label_and_source_file_from_location(
                    context.assembly_location(Some(op_idx)),
                    host,
                );
                Err(match err {
                    IoError::Advice(err) => ExecutionError::AdviceError { label, source_file, err },
                    IoError::Memory(err) => ExecutionError::MemoryError { label, source_file, err },
                    IoError::Operation(err) => {
                        ExecutionError::OperationError { label, source_file, err }
                    },
                    IoError::Execution(_) => unreachable!("handled above"),
                })
            },
            (Err(err), None) => {
                let (label, source_file) = get_label_and_source_file();
                Err(match err {
                    IoError::Advice(err) => ExecutionError::AdviceError { label, source_file, err },
                    IoError::Memory(err) => ExecutionError::MemoryError { label, source_file, err },
                    IoError::Operation(err) => {
                        ExecutionError::OperationError { label, source_file, err }
                    },
                    IoError::Execution(_) => unreachable!("handled above"),
                })
            },
        }
    }
}

// CryptoError implementations
impl<T> MapExecErrWithOpIdx<T> for Result<T, CryptoError> {
    #[inline(always)]
    fn map_exec_err_with_op_idx(self) -> Result<T, ExecutionError> {
        match self {
            Ok(v) => Ok(v),
            Err(err) => {
                let (label, source_file) = get_label_and_source_file();
                Err(match err {
                    CryptoError::Advice(err) => {
                        ExecutionError::AdviceError { label, source_file, err }
                    },
                    CryptoError::Operation(err) => {
                        ExecutionError::OperationError { label, source_file, err }
                    },
                })
            },
        }
    }

    #[inline(always)]
    fn map_exec_err_with_package_source_op_idx(
        self,
        context: Option<PackageSourceDebugContext<'_>>,
        host: &impl BaseHost,
        op_idx: usize,
    ) -> Result<T, ExecutionError> {
        match (self, context) {
            (Ok(v), _) => Ok(v),
            (Err(err), Some(context)) => {
                let (label, source_file) = label_and_source_file_from_location(
                    context.assembly_location(Some(op_idx)),
                    host,
                );
                Err(match err {
                    CryptoError::Advice(err) => {
                        ExecutionError::AdviceError { label, source_file, err }
                    },
                    CryptoError::Operation(err) => ExecutionError::OperationError {
                        label,
                        source_file,
                        err: err.with_package_debug_info(context.debug_info()),
                    },
                })
            },
            (Err(err), None) => {
                let (label, source_file) = get_label_and_source_file();
                Err(match err {
                    CryptoError::Advice(err) => {
                        ExecutionError::AdviceError { label, source_file, err }
                    },
                    CryptoError::Operation(err) => {
                        ExecutionError::OperationError { label, source_file, err }
                    },
                })
            },
        }
    }
}

// AceEvalError implementations
impl<T> MapExecErrWithOpIdx<T> for Result<T, AceEvalError> {
    #[inline(always)]
    fn map_exec_err_with_op_idx(self) -> Result<T, ExecutionError> {
        match self {
            Ok(v) => Ok(v),
            Err(err) => {
                let (label, source_file) = get_label_and_source_file();
                Err(match err {
                    AceEvalError::Ace(error) => {
                        ExecutionError::AceChipError { label, source_file, error }
                    },
                    AceEvalError::Memory(err) => {
                        ExecutionError::MemoryError { label, source_file, err }
                    },
                })
            },
        }
    }

    #[inline(always)]
    fn map_exec_err_with_package_source_op_idx(
        self,
        context: Option<PackageSourceDebugContext<'_>>,
        host: &impl BaseHost,
        op_idx: usize,
    ) -> Result<T, ExecutionError> {
        match (self, context) {
            (Ok(v), _) => Ok(v),
            (Err(err), Some(context)) => {
                let (label, source_file) = label_and_source_file_from_location(
                    context.assembly_location(Some(op_idx)),
                    host,
                );
                Err(match err {
                    AceEvalError::Ace(error) => {
                        ExecutionError::AceChipError { label, source_file, error }
                    },
                    AceEvalError::Memory(err) => {
                        ExecutionError::MemoryError { label, source_file, err }
                    },
                })
            },
            (Err(err), None) => {
                let (label, source_file) = get_label_and_source_file();
                Err(match err {
                    AceEvalError::Ace(error) => {
                        ExecutionError::AceChipError { label, source_file, error }
                    },
                    AceEvalError::Memory(err) => {
                        ExecutionError::MemoryError { label, source_file, err }
                    },
                })
            },
        }
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod error_assertions {
    use alloc::sync::Arc;

    use miden_debug_types::{ByteIndex, SourceId, Uri};
    use miden_mast_package::debug_info::{
        DebugErrorMessage, DebugErrorMessagesSection, DebugSourceAsmOp, DebugSourceMapSection,
        PackageDebugInfo,
    };

    use super::*;

    /// Asserts at compile time that the passed error has Send + Sync + 'static bounds.
    fn _assert_error_is_send_sync_static<E: core::error::Error + Send + Sync + 'static>(_: E) {}

    fn _assert_execution_error_bounds(err: ExecutionError) {
        _assert_error_is_send_sync_static(err);
    }

    struct RecordingHost {
        expected_location: Location,
        returned_span: SourceSpan,
    }

    impl BaseHost for RecordingHost {
        fn get_label_and_source_file(
            &self,
            location: &Location,
        ) -> (SourceSpan, Option<Arc<SourceFile>>) {
            assert_eq!(location, &self.expected_location);
            (self.returned_span, None)
        }
    }

    #[test]
    fn package_source_context_resolves_by_source_occurrence() {
        let source_a = DebugSourceNodeId::from(0);
        let source_b = DebugSourceNodeId::from(1);
        let location_a = Location::new(
            Uri::new("file://pkg/first.masm"),
            ByteIndex::new(10),
            ByteIndex::new(13),
        );
        let location_b = Location::new(
            Uri::new("file://pkg/second.masm"),
            ByteIndex::new(20),
            ByteIndex::new(24),
        );
        let later_location_b = Location::new(
            Uri::new("file://pkg/second-later.masm"),
            ByteIndex::new(30),
            ByteIndex::new(35),
        );
        let debug_info =
            PackageDebugInfo::default().with_source_map(DebugSourceMapSection::from_parts(
                vec![
                    DebugSourceAsmOp::new(
                        source_a,
                        0,
                        Some(location_a),
                        "first".into(),
                        "add".into(),
                        1,
                    ),
                    DebugSourceAsmOp::new(
                        source_b,
                        2,
                        Some(later_location_b),
                        "second_later".into(),
                        "mul".into(),
                        1,
                    ),
                    DebugSourceAsmOp::new(
                        source_b,
                        0,
                        Some(location_b.clone()),
                        "second".into(),
                        "add".into(),
                        1,
                    ),
                ],
                Vec::new(),
            ));
        let host = RecordingHost {
            expected_location: location_b,
            returned_span: SourceSpan::new(SourceId::new(7), 20u32..24),
        };
        let context = PackageSourceDebugContext::new(&debug_info, source_b);

        assert_eq!(context.assembly_location(None), Some(&host.expected_location));

        let err = OperationError::DivideByZero.with_package_source_context(context, &host, Some(0));

        match err {
            ExecutionError::OperationError { label, source_file, err } => {
                assert_eq!(label, host.returned_span);
                assert!(source_file.is_none());
                assert!(matches!(err, OperationError::DivideByZero));
            },
            err => panic!("expected operation error, got {err:?}"),
        }
    }

    #[test]
    fn package_source_context_without_location_uses_unknown_span() {
        let source_node_id = DebugSourceNodeId::from(0);
        let debug_info =
            PackageDebugInfo::default().with_source_map(DebugSourceMapSection::from_parts(
                vec![DebugSourceAsmOp::new(
                    source_node_id,
                    0,
                    None,
                    "missing_location".into(),
                    "add".into(),
                    1,
                )],
                Vec::new(),
            ));
        let host = RecordingHost {
            expected_location: Location::new(
                Uri::new("file://unused.masm"),
                ByteIndex::new(0),
                ByteIndex::new(0),
            ),
            returned_span: SourceSpan::new(SourceId::new(7), 20u32..24),
        };
        let context = PackageSourceDebugContext::new(&debug_info, source_node_id);

        let err = advice_error_with_package_source_context(
            AdviceError::StackReadFailed,
            context,
            &host,
            Some(0),
        );

        match err {
            ExecutionError::AdviceError { label, source_file, err } => {
                assert_eq!(label, SourceSpan::UNKNOWN);
                assert!(source_file.is_none());
                assert!(matches!(err, AdviceError::StackReadFailed));
            },
            err => panic!("expected advice error, got {err:?}"),
        }
    }

    #[test]
    fn package_debug_info_without_source_node_restores_error_message() {
        let debug_info =
            PackageDebugInfo::default().with_error_messages(DebugErrorMessagesSection::from_parts(
                vec![DebugErrorMessage::new(7, Arc::from("some error message"))],
            ));
        let context = PackageSourceDebugContext::new_optional(&debug_info, None);
        let err = Err::<(), _>(OperationError::FailedAssertion {
            err_code: Felt::from_u32(7),
            err_msg: None,
        })
        .map_exec_err_with_package_source_op_idx(
            Some(context),
            &RecordingHost {
                expected_location: Location::new(
                    Uri::new("file://unused.masm"),
                    ByteIndex::new(0),
                    ByteIndex::new(0),
                ),
                returned_span: SourceSpan::new(SourceId::new(7), 20u32..24),
            },
            0,
        )
        .unwrap_err();

        match err {
            ExecutionError::OperationError {
                label,
                source_file,
                err: OperationError::FailedAssertion { err_msg, .. },
            } => {
                assert_eq!(label, SourceSpan::UNKNOWN);
                assert!(source_file.is_none());
                assert_eq!(err_msg.as_deref(), Some("some error message"));
            },
            err => panic!("expected failed assertion operation error, got {err:?}"),
        }
    }

    #[test]
    fn package_debug_info_restores_merkle_path_error_message() {
        let debug_info =
            PackageDebugInfo::default().with_error_messages(DebugErrorMessagesSection::from_parts(
                vec![DebugErrorMessage::new(7, Arc::from("some error message"))],
            ));
        let err = OperationError::MerklePathVerificationFailed {
            inner: Box::new(MerklePathVerificationFailedInner {
                value: Word::default(),
                index: Felt::from_u32(3),
                root: Word::default(),
                err_code: Felt::from_u32(7),
                err_msg: None,
            }),
        }
        .with_package_debug_info(&debug_info);

        match err {
            OperationError::MerklePathVerificationFailed { inner } => {
                assert_eq!(inner.err_msg.as_deref(), Some("some error message"));
            },
            err => panic!("expected MerklePathVerificationFailed, got {err:?}"),
        }
    }
}
