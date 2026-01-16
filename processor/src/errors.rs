// Allow unused assignments - required by miette::Diagnostic derive macro
#![allow(unused_assignments)]

use alloc::{boxed::Box, string::String, sync::Arc, vec::Vec};

use miden_air::trace::{RowIndex, RowIndex as AirRowIndex};
use miden_core::{
    EventId, EventName, Felt, Word,
    field::QuadFelt,
    mast::{MastForest, MastNodeId},
    stack::MIN_STACK_DEPTH,
    utils::to_hex,
};
use miden_debug_types::{SourceFile, SourceSpan};
use miden_utils_diagnostics::{Diagnostic, miette};

use crate::{BaseHost, DebugError, EventError, MemoryError, TraceError, host::advice::AdviceError};

// EXECUTION ERROR
// ================================================================================================

#[derive(Debug, thiserror::Error, Diagnostic)]
pub enum ExecutionError {
    #[error("advice provider error at clock cycle {clk}")]
    #[diagnostic()]
    AdviceError {
        #[label]
        label: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
        clk: RowIndex,
        #[source]
        #[diagnostic_source]
        err: AdviceError,
    },
    #[error("debug handler error at clock cycle {clk}: {err}")]
    DebugHandlerError {
        clk: RowIndex,
        #[source]
        err: DebugError,
    },
    #[error("trace handler error at clock cycle {clk} for trace ID {trace_id}: {err}")]
    TraceHandlerError {
        clk: RowIndex,
        trace_id: u32,
        #[source]
        err: TraceError,
    },
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
    #[error("attempted to add event handler for '{event}' (already registered)")]
    DuplicateEventHandler { event: EventName },
    #[error("attempted to add event handler for '{event}' (reserved system event)")]
    ReservedEventNamespace { event: EventName },
    #[error("failed to execute the program for internal reason: {0}")]
    Internal(&'static str),
    /// Memory error with source context for diagnostics.
    ///
    /// Use `MemoryResultExt::map_mem_err` to convert `Result<T, MemoryError>` with context.
    #[error("memory error")]
    #[diagnostic()]
    MemoryError {
        #[label]
        label: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
        #[source]
        #[diagnostic_source]
        err: MemoryError,
    },
    /// Memory error without source context (for internal operations like FMP initialization).
    ///
    /// Use `ExecutionError::MemoryErrorNoCtx` for memory errors that don't have error context
    /// available (e.g., during call/syscall context initialization).
    #[error(transparent)]
    #[diagnostic(transparent)]
    MemoryErrorNoCtx(MemoryError),
    #[error("stack should have at most {MIN_STACK_DEPTH} elements at the end of program execution, but had {} elements", MIN_STACK_DEPTH + .0)]
    OutputStackOverflow(usize),
    #[error("failed to execute arithmetic circuit evaluation operation: {error}")]
    #[diagnostic()]
    AceChipError {
        #[label("this call failed")]
        label: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
        error: AceError,
    },
    #[error("failed to serialize proof: {0}")]
    ProofSerializationError(String),
    #[error("operation error at clock cycle {clk}")]
    #[diagnostic()]
    OperationError {
        #[label]
        label: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
        clk: AirRowIndex,
        #[source]
        #[diagnostic_source]
        err: OperationError,
    },
}

impl AsRef<dyn Diagnostic> for ExecutionError {
    fn as_ref(&self) -> &(dyn Diagnostic + 'static) {
        self
    }
}

// ACE ERROR
// ================================================================================================

#[derive(Debug, thiserror::Error)]
pub enum AceError {
    #[error("num of variables should be word aligned and non-zero but was {0}")]
    NumVarIsNotWordAlignedOrIsEmpty(u64),
    #[error("num of evaluation gates should be word aligned and non-zero but was {0}")]
    NumEvalIsNotWordAlignedOrIsEmpty(u64),
    #[error("circuit does not evaluate to zero")]
    CircuitNotEvaluateZero,
    #[error("failed to read from memory")]
    FailedMemoryRead,
    #[error("failed to decode instruction")]
    FailedDecodeInstruction,
    #[error("failed to read from the wiring bus")]
    FailedWireBusRead,
    #[error("num of wires must be less than 2^30 but was {0}")]
    TooManyWires(u64),
}

// OPERATION ERROR
// ================================================================================================

/// Lightweight error type for operations that can fail.
///
/// This enum captures error conditions without expensive context information (no
/// source location, no file references). When an `OperationError` propagates up
/// to become an `ExecutionError`, the context is resolved lazily via extension
/// traits like `OperationResultExt::map_exec_err`.
///
/// # Adding new errors (for contributors)
///
/// **Use `OperationError` when:**
/// - The error occurs during operation execution (e.g., assertion failures, type mismatches)
/// - Context can be resolved at the call site via `err_ctx.label_and_source_file()`
/// - The error needs both a human-readable message and optional diagnostic help
///
/// **Avoid duplicating error context.** If context comes from the call site via
/// `ErrorContext`, do NOT add `label` or `source_file` fields to the variant.
///
/// **Pattern at call sites:**
/// ```ignore
/// // Return OperationError and let the caller wrap it:
/// fn some_op() -> Result<(), OperationError> {
///     Err(OperationError::DivideByZero)
/// }
///
/// // Caller wraps with context lazily:
/// some_op().map_exec_err(err_ctx, clk)?;
/// ```
///
/// For wrapper errors (`AdviceError`, `EventError`, `AceError`), use the
/// corresponding extension traits: `AdviceResultExt`, `EventResultExt`,
/// `AceResultExt`.
#[derive(Debug, Clone, thiserror::Error, Diagnostic)]
pub enum OperationError {
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
    #[error("attempted to calculate integer logarithm with zero argument")]
    #[diagnostic(help("ilog2 requires a non-zero argument"))]
    LogArgumentZero,
    #[error("external node with mast root {0} resolved to an external node")]
    CircularExternalNode(Word),
    #[error("FRI domain segment value cannot exceed 3, but was {0}")]
    InvalidFriDomainSegment(u64),
    #[error("degree-respecting projection is inconsistent: expected {0} but was {1}")]
    InvalidFriLayerFolding(QuadFelt, QuadFelt),
    #[error("FRI domain size was 0")]
    InvalidFriDomainGenerator,
    #[error("failed to execute dynamic code block; block with root {digest} could not be found")]
    DynamicNodeNotFound { digest: Word },
    #[error("syscall failed: procedure with root {proc_root} was not found in the kernel")]
    SyscallTargetNotInKernel { proc_root: Word },
    #[error("when returning from a call, stack depth must be {MIN_STACK_DEPTH}, but was {depth}")]
    InvalidStackDepthOnReturn { depth: usize },
    #[error("no MAST forest contains the procedure with root digest {root_digest}")]
    NoMastForestWithProcedure { root_digest: Word },
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
    #[error(
        "invalid crypto operation: Merkle path length {path_len} does not match expected depth {depth}"
    )]
    InvalidMerklePathLength { path_len: usize, depth: Felt },
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

/// Extension trait for converting `Result<T, OperationError>` to `Result<T, ExecutionError>`.
///
/// This trait provides methods to wrap an `OperationError` with execution context
/// (source location, clock cycle) at the point where the error needs to be propagated.
pub trait OperationResultExt<T> {
    /// Maps an `OperationError` to an `ExecutionError` with the provided context.
    ///
    /// The `err_ctx` parameter provides source location information, and `clk` is the
    /// clock cycle at which the error occurred.
    fn map_exec_err(
        self,
        err_ctx: &impl ErrorContext,
        clk: AirRowIndex,
    ) -> Result<T, ExecutionError>;
}

impl<T> OperationResultExt<T> for Result<T, OperationError> {
    fn map_exec_err(
        self,
        err_ctx: &impl ErrorContext,
        clk: AirRowIndex,
    ) -> Result<T, ExecutionError> {
        self.map_err(|err| {
            let (label, source_file) = err_ctx.label_and_source_file();
            ExecutionError::OperationError { label, source_file, clk, err }
        })
    }
}

/// Extension trait for converting `Result<T, AdviceError>` to `Result<T, ExecutionError>`.
pub trait AdviceResultExt<T> {
    /// Maps an `AdviceError` to an `ExecutionError` with the provided context.
    fn map_advice_err(
        self,
        err_ctx: &impl ErrorContext,
        clk: RowIndex,
    ) -> Result<T, ExecutionError>;
}

impl<T> AdviceResultExt<T> for Result<T, AdviceError> {
    fn map_advice_err(
        self,
        err_ctx: &impl ErrorContext,
        clk: RowIndex,
    ) -> Result<T, ExecutionError> {
        self.map_err(|err| {
            let (label, source_file) = err_ctx.label_and_source_file();
            ExecutionError::AdviceError { label, source_file, clk, err }
        })
    }
}

/// Extension trait for converting `Result<T, EventError>` to `Result<T, ExecutionError>`.
pub trait EventResultExt<T> {
    /// Maps an `EventError` to an `ExecutionError` with the provided context.
    fn map_event_err(
        self,
        err_ctx: &impl ErrorContext,
        event_id: EventId,
        event_name: Option<EventName>,
    ) -> Result<T, ExecutionError>;
}

impl<T> EventResultExt<T> for Result<T, EventError> {
    fn map_event_err(
        self,
        err_ctx: &impl ErrorContext,
        event_id: EventId,
        event_name: Option<EventName>,
    ) -> Result<T, ExecutionError> {
        self.map_err(|error| {
            let (label, source_file) = err_ctx.label_and_source_file();
            ExecutionError::EventError {
                label,
                source_file,
                event_id,
                event_name,
                error,
            }
        })
    }
}

/// Extension trait for converting `Result<T, AceError>` to `Result<T, ExecutionError>`.
pub trait AceResultExt<T> {
    /// Maps an `AceError` to an `ExecutionError` with the provided context.
    fn map_ace_err(self, err_ctx: &impl ErrorContext) -> Result<T, ExecutionError>;
}

impl<T> AceResultExt<T> for Result<T, AceError> {
    fn map_ace_err(self, err_ctx: &impl ErrorContext) -> Result<T, ExecutionError> {
        self.map_err(|error| {
            let (label, source_file) = err_ctx.label_and_source_file();
            ExecutionError::AceChipError { label, source_file, error }
        })
    }
}

/// Extension trait for converting `Result<T, MemoryError>` to `Result<T, ExecutionError>`.
pub trait MemoryResultExt<T> {
    /// Maps a `MemoryError` to an `ExecutionError` with the provided context.
    fn map_mem_err(self, err_ctx: &impl ErrorContext) -> Result<T, ExecutionError>;
}

impl<T> MemoryResultExt<T> for Result<T, MemoryError> {
    fn map_mem_err(self, err_ctx: &impl ErrorContext) -> Result<T, ExecutionError> {
        self.map_err(|err| {
            let (label, source_file) = err_ctx.label_and_source_file();
            ExecutionError::MemoryError { label, source_file, err }
        })
    }
}

// ERROR CONTEXT
// ===============================================================================================

/// Constructs an error context for the given node in the MAST forest.
///
/// When the `no_err_ctx` feature is disabled, this macro returns a proper error context; otherwise,
/// it returns `()`. That is, this macro is designed to be zero-cost when the `no_err_ctx` feature
/// is enabled.
///
/// Usage:
/// - `err_ctx!(mast_forest, node, source_manager)` - creates basic error context
/// - `err_ctx!(mast_forest, node, source_manager, op_idx)` - creates error context with operation
///   index
#[cfg(not(feature = "no_err_ctx"))]
#[macro_export]
macro_rules! err_ctx {
    ($mast_forest:expr, $node:expr, $host:expr, $in_debug_mode:expr) => {
        $crate::errors::ErrorContextImpl::new($mast_forest, $node, $host, $in_debug_mode)
    };
    ($mast_forest:expr, $node:expr, $host:expr, $in_debug_mode:expr, $op_idx:expr) => {
        $crate::errors::ErrorContextImpl::new_with_op_idx(
            $mast_forest,
            $node,
            $host,
            $in_debug_mode,
            $op_idx,
        )
    };
}

/// Constructs an error context for the given node in the MAST forest.
///
/// When the `no_err_ctx` feature is disabled, this macro returns a proper error context; otherwise,
/// it returns `()`. That is, this macro is designed to be zero-cost when the `no_err_ctx` feature
/// is enabled.
///
/// Usage:
/// - `err_ctx!(mast_forest, node, source_manager)` - creates basic error context
/// - `err_ctx!(mast_forest, node, source_manager, op_idx)` - creates error context with operation
///   index
#[cfg(feature = "no_err_ctx")]
#[macro_export]
macro_rules! err_ctx {
    ($mast_forest:expr, $node:expr, $host:expr, $in_debug_mode:expr) => {
        ()
    };
    ($mast_forest:expr, $node:expr, $host:expr, $in_debug_mode:expr, $op_idx:expr) => {
        ()
    };
}

/// Trait defining the interface for error context providers.
///
/// This trait contains the same methods as `ErrorContext` to provide a common
/// interface for error context functionality.
pub trait ErrorContext {
    /// Returns the label and source file associated with the error context, if any.
    ///
    /// Note that `SourceSpan::UNKNOWN` will be returned to indicate an empty span.
    fn label_and_source_file(&self) -> (SourceSpan, Option<Arc<SourceFile>>);
}

/// Context information to be used when reporting errors.
pub struct ErrorContextImpl {
    label: SourceSpan,
    source_file: Option<Arc<SourceFile>>,
}

impl ErrorContextImpl {
    pub fn new(
        mast_forest: &MastForest,
        node_id: MastNodeId,
        host: &impl BaseHost,
        in_debug_mode: bool,
    ) -> Self {
        let (label, source_file) =
            Self::precalc_label_and_source_file(None, mast_forest, node_id, host, in_debug_mode);
        Self { label, source_file }
    }

    pub fn new_with_op_idx(
        mast_forest: &MastForest,
        node_id: MastNodeId,
        host: &impl BaseHost,
        in_debug_mode: bool,
        op_idx: usize,
    ) -> Self {
        let op_idx = op_idx.into();
        let (label, source_file) =
            Self::precalc_label_and_source_file(op_idx, mast_forest, node_id, host, in_debug_mode);
        Self { label, source_file }
    }

    fn precalc_label_and_source_file(
        op_idx: Option<usize>,
        mast_forest: &MastForest,
        node_id: MastNodeId,
        host: &impl BaseHost,
        in_debug_mode: bool,
    ) -> (SourceSpan, Option<Arc<SourceFile>>) {
        // When not in debug mode, skip the expensive decorator traversal entirely.
        // Decorators (including AsmOp decorators used for error context) should only
        // be accessed when debugging is enabled.
        if !in_debug_mode {
            return (SourceSpan::UNKNOWN, None);
        }

        mast_forest
            .get_assembly_op(node_id, op_idx)
            .and_then(|assembly_op| assembly_op.location())
            .map_or_else(
                || (SourceSpan::UNKNOWN, None),
                |location| host.get_label_and_source_file(location),
            )
    }
}

impl ErrorContext for ErrorContextImpl {
    fn label_and_source_file(&self) -> (SourceSpan, Option<Arc<SourceFile>>) {
        (self.label, self.source_file.clone())
    }
}

impl ErrorContext for () {
    fn label_and_source_file(&self) -> (SourceSpan, Option<Arc<SourceFile>>) {
        (SourceSpan::UNKNOWN, None)
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
