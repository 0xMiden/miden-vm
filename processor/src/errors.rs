// Allow unused assignments - required by miette::Diagnostic derive macro
#![allow(unused_assignments)]

use alloc::{boxed::Box, string::String, sync::Arc, vec::Vec};

use miden_core::program::MIN_STACK_DEPTH;
use miden_debug_types::{SourceFile, SourceSpan};
use miden_utils_diagnostics::{Diagnostic, miette};

use crate::{
    ContextId, DebugError, Felt, Host, TraceError, Word,
    advice::AdviceError,
    event::{EventError, EventId, EventName},
    fast::SystemEventError,
    mast::{MastForest, MastNodeId},
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
        Some(name) => format!("'{}' (ID: {})", name, event_id),
        None => format!("with ID: {}", event_id),
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
    #[error("failed to execute the program for internal reason: {0}")]
    Internal(&'static str),
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
    #[error("failed to serialize proof: {0}")]
    ProofSerializationError(String),
    #[error(transparent)]
    HostError(#[from] HostError),
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

/// Error type for host-related operations (event handlers, debug handlers, trace handlers).
#[derive(Debug, thiserror::Error)]
pub enum HostError {
    #[error("attempted to add event handler for '{event}' (already registered)")]
    DuplicateEventHandler { event: EventName },
    #[error("attempted to add event handler for '{event}' (reserved system event)")]
    ReservedEventNamespace { event: EventName },
    #[error("debug handler error: {err}")]
    DebugHandlerError {
        #[source]
        err: DebugError,
    },
    #[error("trace handler error for trace ID {trace_id}: {err}")]
    TraceHandlerError {
        trace_id: u32,
        #[source]
        err: TraceError,
    },
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
    #[error("word access at memory address {addr} in context {ctx} is unaligned")]
    #[diagnostic(help(
        "ensure that the memory address accessed is aligned to a word boundary (it is a multiple of 4)"
    ))]
    UnalignedWordAccess { addr: u32, ctx: ContextId },
    #[error("failed to read from memory: {0}")]
    MemoryReadFailed(String),
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
/// some_op().map_exec_err(mast_forest, node_id, host)?;
/// ```
///
/// For wrapper errors (`AdviceError`, `EventError`, `AceError`), use the corresponding extension
/// traits (`AdviceResultExt`, `AceResultExt`) or helper functions (`advice_error_with_context`,
/// `event_error_with_context`).
#[derive(Debug, Clone, thiserror::Error, Diagnostic)]
pub enum OperationError {
    #[error("external node with mast root {0} resolved to an external node")]
    CircularExternalNode(Word),
    #[error("division by zero")]
    #[diagnostic(help(
        "ensure the divisor (second stack element) is non-zero before division or modulo operations"
    ))]
    DivideByZero,
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
    #[error("FRI operation failed: {0}")]
    FriError(String),
    #[error(
        "invalid crypto operation: Merkle path length {path_len} does not match expected depth {depth}"
    )]
    InvalidMerklePathLength { path_len: usize, depth: Felt },
    #[error("when returning from a call, stack depth must be {MIN_STACK_DEPTH}, but was {depth}")]
    InvalidStackDepthOnReturn { depth: usize },
    #[error("attempted to calculate integer logarithm with zero argument")]
    #[diagnostic(help("ilog2 requires a non-zero argument"))]
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
    #[error("operation expected a binary value, but got {value}")]
    NotBinaryValue { value: Felt },
    #[error("if statement expected a binary value on top of the stack, but got {value}")]
    NotBinaryValueIf { value: Felt },
    #[error("loop condition must be a binary value, but got {value}")]
    #[diagnostic(help(
        "this could happen either when first entering the loop, or any subsequent iteration"
    ))]
    NotBinaryValueLoop { value: Felt },
    #[error("operation expected u32 values, but got values: {values:?}")]
    NotU32Values { values: Vec<Felt> },
    #[error("syscall failed: procedure with root {proc_root} was not found in the kernel")]
    SyscallTargetNotInKernel { proc_root: Word },
    #[error("failed to execute the operation for internal reason: {0}")]
    Internal(&'static str),
}

impl OperationError {
    /// Wraps this error with execution context to produce an `ExecutionError`.
    ///
    /// This is useful when working with `ControlFlow` or other non-`Result` return types
    /// where the `OperationResultExt::map_exec_err` extension trait cannot be used directly.
    pub fn with_context(
        self,
        mast_forest: &MastForest,
        node_id: MastNodeId,
        host: &impl Host,
    ) -> ExecutionError {
        let (label, source_file) = get_label_and_source_file(None, mast_forest, node_id, host);
        ExecutionError::OperationError { label, source_file, err: self }
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

/// Computes the label and source file for error context.
///
/// This function is called by the extension traits to compute source location
/// only when an error occurs. Since errors are rare, the cost of decorator
/// traversal is acceptable.
fn get_label_and_source_file(
    op_idx: Option<usize>,
    mast_forest: &MastForest,
    node_id: MastNodeId,
    host: &impl Host,
) -> (SourceSpan, Option<Arc<SourceFile>>) {
    mast_forest
        .get_assembly_op(node_id, op_idx)
        .and_then(|assembly_op| assembly_op.location())
        .map_or_else(
            || (SourceSpan::UNKNOWN, None),
            |location| host.get_label_and_source_file(location),
        )
}

/// Wraps an `AdviceError` with execution context to produce an `ExecutionError`.
///
/// This is useful when working with `ControlFlow` or other non-`Result` return types
/// where the extension traits cannot be used directly.
pub fn advice_error_with_context(
    err: AdviceError,
    mast_forest: &MastForest,
    node_id: MastNodeId,
    host: &impl Host,
) -> ExecutionError {
    let (label, source_file) = get_label_and_source_file(None, mast_forest, node_id, host);
    ExecutionError::AdviceError { label, source_file, err }
}

/// Wraps an `EventError` with execution context to produce an `ExecutionError`.
///
/// This is useful when working with `ControlFlow` or other non-`Result` return types
/// where an extension trait on `Result` cannot be used directly.
pub fn event_error_with_context(
    error: EventError,
    mast_forest: &MastForest,
    node_id: MastNodeId,
    host: &impl Host,
    event_id: EventId,
    event_name: Option<EventName>,
) -> ExecutionError {
    let (label, source_file) = get_label_and_source_file(None, mast_forest, node_id, host);
    ExecutionError::EventError {
        label,
        source_file,
        event_id,
        event_name,
        error,
    }
}

/// Creates a `ProcedureNotFound` error with execution context.
pub fn procedure_not_found_with_context(
    root_digest: Word,
    mast_forest: &MastForest,
    node_id: MastNodeId,
    host: &impl Host,
) -> ExecutionError {
    let (label, source_file) = get_label_and_source_file(None, mast_forest, node_id, host);
    ExecutionError::ProcedureNotFound { label, source_file, root_digest }
}

// CONSOLIDATED EXTENSION TRAITS (plafer's approach)
// ================================================================================================
//
// Three traits organized by method signature rather than by error type:
// 1. MapExecErr - for errors with basic context (forest, node_id, host)
// 2. MapExecErrWithOpIdx - for errors in basic blocks that need op_idx
// 3. MapExecErrNoCtx - for errors without any context

/// Extension trait for mapping errors to `ExecutionError` with basic context.
///
/// Implement this for error types that can be converted to `ExecutionError` using
/// just the MAST forest, node ID, and host for source location lookup.
pub trait MapExecErr<T> {
    fn map_exec_err(
        self,
        mast_forest: &MastForest,
        node_id: MastNodeId,
        host: &impl Host,
    ) -> Result<T, ExecutionError>;
}

/// Extension trait for mapping errors to `ExecutionError` with op index context.
///
/// Implement this for error types that occur within basic blocks where the
/// operation index is available for more precise source location.
pub trait MapExecErrWithOpIdx<T> {
    fn map_exec_err_with_op_idx(
        self,
        mast_forest: &MastForest,
        node_id: MastNodeId,
        host: &impl Host,
        op_idx: usize,
    ) -> Result<T, ExecutionError>;
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
    fn map_exec_err(
        self,
        mast_forest: &MastForest,
        node_id: MastNodeId,
        host: &impl Host,
    ) -> Result<T, ExecutionError> {
        match self {
            Ok(v) => Ok(v),
            Err(err) => {
                let (label, source_file) =
                    get_label_and_source_file(None, mast_forest, node_id, host);
                Err(ExecutionError::OperationError { label, source_file, err })
            },
        }
    }
}

impl<T> MapExecErrWithOpIdx<T> for Result<T, OperationError> {
    #[inline(always)]
    fn map_exec_err_with_op_idx(
        self,
        mast_forest: &MastForest,
        node_id: MastNodeId,
        host: &impl Host,
        op_idx: usize,
    ) -> Result<T, ExecutionError> {
        match self {
            Ok(v) => Ok(v),
            Err(err) => {
                let (label, source_file) =
                    get_label_and_source_file(Some(op_idx), mast_forest, node_id, host);
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
    fn map_exec_err(
        self,
        mast_forest: &MastForest,
        node_id: MastNodeId,
        host: &impl Host,
    ) -> Result<T, ExecutionError> {
        match self {
            Ok(v) => Ok(v),
            Err(err) => Err(advice_error_with_context(err, mast_forest, node_id, host)),
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
    fn map_exec_err(
        self,
        mast_forest: &MastForest,
        node_id: MastNodeId,
        host: &impl Host,
    ) -> Result<T, ExecutionError> {
        match self {
            Ok(v) => Ok(v),
            Err(err) => {
                let (label, source_file) =
                    get_label_and_source_file(None, mast_forest, node_id, host);
                Err(ExecutionError::MemoryError { label, source_file, err })
            },
        }
    }
}

impl<T> MapExecErrWithOpIdx<T> for Result<T, MemoryError> {
    #[inline(always)]
    fn map_exec_err_with_op_idx(
        self,
        mast_forest: &MastForest,
        node_id: MastNodeId,
        host: &impl Host,
        op_idx: usize,
    ) -> Result<T, ExecutionError> {
        match self {
            Ok(v) => Ok(v),
            Err(err) => {
                let (label, source_file) =
                    get_label_and_source_file(Some(op_idx), mast_forest, node_id, host);
                Err(ExecutionError::MemoryError { label, source_file, err })
            },
        }
    }
}

// SystemEventError implementations
impl<T> MapExecErr<T> for Result<T, SystemEventError> {
    #[inline(always)]
    fn map_exec_err(
        self,
        mast_forest: &MastForest,
        node_id: MastNodeId,
        host: &impl Host,
    ) -> Result<T, ExecutionError> {
        match self {
            Ok(v) => Ok(v),
            Err(err) => {
                let (label, source_file) =
                    get_label_and_source_file(None, mast_forest, node_id, host);
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
                })
            },
        }
    }
}

impl<T> MapExecErrWithOpIdx<T> for Result<T, SystemEventError> {
    #[inline(always)]
    fn map_exec_err_with_op_idx(
        self,
        mast_forest: &MastForest,
        node_id: MastNodeId,
        host: &impl Host,
        op_idx: usize,
    ) -> Result<T, ExecutionError> {
        match self {
            Ok(v) => Ok(v),
            Err(err) => {
                let (label, source_file) =
                    get_label_and_source_file(Some(op_idx), mast_forest, node_id, host);
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
                })
            },
        }
    }
}

// IoError implementations
impl<T> MapExecErrWithOpIdx<T> for Result<T, IoError> {
    #[inline(always)]
    fn map_exec_err_with_op_idx(
        self,
        mast_forest: &MastForest,
        node_id: MastNodeId,
        host: &impl Host,
        op_idx: usize,
    ) -> Result<T, ExecutionError> {
        match self {
            Ok(v) => Ok(v),
            Err(err) => {
                let (label, source_file) =
                    get_label_and_source_file(Some(op_idx), mast_forest, node_id, host);
                Err(match err {
                    IoError::Advice(err) => ExecutionError::AdviceError { label, source_file, err },
                    IoError::Memory(err) => ExecutionError::MemoryError { label, source_file, err },
                    // Execution errors are already fully formed with their own message.
                    IoError::Execution(boxed_err) => *boxed_err,
                })
            },
        }
    }
}

// CryptoError implementations
impl<T> MapExecErrWithOpIdx<T> for Result<T, CryptoError> {
    #[inline(always)]
    fn map_exec_err_with_op_idx(
        self,
        mast_forest: &MastForest,
        node_id: MastNodeId,
        host: &impl Host,
        op_idx: usize,
    ) -> Result<T, ExecutionError> {
        match self {
            Ok(v) => Ok(v),
            Err(err) => {
                let (label, source_file) =
                    get_label_and_source_file(Some(op_idx), mast_forest, node_id, host);
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
    fn map_exec_err_with_op_idx(
        self,
        mast_forest: &MastForest,
        node_id: MastNodeId,
        host: &impl Host,
        op_idx: usize,
    ) -> Result<T, ExecutionError> {
        match self {
            Ok(v) => Ok(v),
            Err(err) => {
                let (label, source_file) =
                    get_label_and_source_file(Some(op_idx), mast_forest, node_id, host);
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
    use super::*;

    /// Asserts at compile time that the passed error has Send + Sync + 'static bounds.
    fn _assert_error_is_send_sync_static<E: core::error::Error + Send + Sync + 'static>(_: E) {}

    fn _assert_execution_error_bounds(err: ExecutionError) {
        _assert_error_is_send_sync_static(err);
    }
}
