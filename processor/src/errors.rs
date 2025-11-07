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
//!    (decoders, fast processor, basic block executors) using [`ExecutionError::from_operation`].
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
//! let err_ctx = err_ctx!(program, node, op_idx);
//! self.execute_op(op)
//!     .map_err(|err| ExecutionError::from_operation(&err_ctx, err))?;
//! ```
//!
//! ## Error Context Feature Flag
//!
//! The `no_err_ctx` feature flag allows compile-time elimination of error context for
//! performance-critical builds. When enabled, the `err_ctx!()` macro expands to `()` and all
//! context operations become no-ops.

use alloc::{sync::Arc, vec::Vec};

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
    #[error("{err}")]
    #[diagnostic()]
    OperationError {
        #[label]
        label: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
        err: OperationError,
    },
    #[error("external node with mast root {0} resolved to an external node")]
    CircularExternalNode(Word),
    #[error("exceeded the allowed number of max cycles {0}")]
    CycleLimitExceeded(u32),
    #[error("decorator id {decorator_id} does not exist in MAST forest")]
    DecoratorNotFoundInForest { decorator_id: DecoratorId },
    #[error("attempted to add event handler for '{event}' (already registered)")]
    DuplicateEventHandler { event: EventName },
    #[error("attempted to add event handler for '{event}' (reserved system event)")]
    ReservedEventNamespace { event: EventName },
    #[error("failed to execute the program for internal reason: {0}")]
    FailedToExecuteProgram(&'static str),
    #[error("node id {node_id} does not exist in MAST forest")]
    MastNodeNotFoundInForest { node_id: MastNodeId },
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

impl ExecutionError {
    pub fn from_operation(err_ctx: &impl ErrorContext, err: OperationError) -> Self {
        let (label, source_file) = err_ctx.label_and_source_file();
        Self::OperationError { label, source_file, err }
    }

    pub fn from_operation_with_label(
        label: SourceSpan,
        source_file: Option<Arc<SourceFile>>,
        err: OperationError,
    ) -> Self {
        Self::OperationError { label, source_file, err }
    }
}

impl AsRef<dyn Diagnostic> for ExecutionError {
    fn as_ref(&self) -> &(dyn Diagnostic + 'static) {
        self
    }
}

// OPERATION ERROR
// ================================================================================================

#[derive(Debug, thiserror::Error)]
pub enum OperationError {
    // NOTE: AdviceError has Diagnostic attributes with help text - restore at end of refactor
    #[error("advice provider error at clock cycle {clk}")]
    AdviceError {
        clk: RowIndex,
        #[source]
        err: AdviceError,
    },
    #[error(
        "failed to execute the dynamic code block provided by the stack with root {hex}; the block could not be found",
        hex = .digest.to_hex()
    )]
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
        "assertion failed at clock cycle {clk} with error {}",
        match err_msg {
            Some(msg) => format!("message: {msg}"),
            None => format!("code: {err_code}"),
        }
    )]
    FailedAssertion {
        clk: RowIndex,
        err_code: Felt,
        err_msg: Option<Arc<str>>,
    },
    #[error("stack overflow: exceeded maximum stack depth")]
    StackOverflow,
    #[error("division by zero at clock cycle {clk}")]
    DivideByZero { clk: RowIndex },
    #[error(
        "when returning from a call or dyncall, stack depth must be {MIN_STACK_DEPTH}, but was {depth}"
    )]
    // NOTE: Diagnostic label "when returning from this call site" will be restored
    // when implementing OperationDiagnostic trait (deferred).
    InvalidStackDepthOnReturn { depth: usize },
    #[error("exceeded the allowed number of max cycles {max_cycles}")]
    CycleLimitExceeded { max_cycles: u32 },
    #[error("attempted to calculate integer logarithm with zero argument at clock cycle {clk}")]
    LogArgumentZero { clk: RowIndex },
    #[error("malformed signature key: {key_type}")]
    // NOTE: Diagnostic help "the secret key associated with the provided public key is malformed"
    // will be restored when implementing OperationDiagnostic trait (deferred).
    MalformedSignatureKey { key_type: &'static str },
    #[error(
        "MAST forest in host indexed by procedure root {root_digest} doesn't contain that root"
    )]
    MalformedMastForestInHost { root_digest: Word },
    #[error("no MAST forest contains the procedure with root digest {root_digest}")]
    NoMastForestWithProcedure { root_digest: Word },
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
    #[error("if statement expected a binary value on top of the stack, but got {value}")]
    NotBinaryValueIf { value: Felt },
    #[error("operation expected a binary value, but got {value}")]
    NotBinaryValueOp { value: Felt },
    #[error("loop condition must be a binary value, but got {value}")]
    // NOTE: Diagnostic help "this could happen either when first entering the loop, or any
    // subsequent iteration" will be restored when implementing OperationDiagnostic trait
    // (deferred).
    NotBinaryValueLoop { value: Felt },
    #[error("operation expected u32 values, but got values: {values:?} (error code: {err_code})")]
    NotU32Values { values: Vec<Felt>, err_code: Felt },
    #[error(
        "Operand stack input is {input} but it is expected to fit in a u32 at clock cycle {clk}"
    )]
    NotU32StackValue { clk: RowIndex, input: u64 },
    #[error("smt node {node_hex} not found", node_hex = to_hex(node.as_bytes()))]
    SmtNodeNotFound { node: Word },
    #[error(
        "expected pre-image length of node {node_hex} to be a multiple of 8 but was {preimage_len}",
        node_hex = to_hex(node.as_bytes())
    )]
    SmtNodePreImageNotValid { node: Word, preimage_len: usize },
    #[error(
        "syscall failed: procedure with root {hex} was not found in the kernel",
        hex = to_hex(proc_root.as_bytes())
    )]
    SyscallTargetNotInKernel { proc_root: Word },
    #[error("failed to execute arithmetic circuit evaluation operation: {0}")]
    // NOTE: Diagnostic label "this call failed" will be restored when implementing
    // OperationDiagnostic trait (deferred).
    AceChipError(#[source] AceError),
    #[error("FRI domain segment value cannot exceed 3, but was {0}")]
    InvalidFriDomainSegment(u64),
    #[error("degree-respecting projection is inconsistent: expected {0} but was {1}")]
    InvalidFriLayerFolding(QuadFelt, QuadFelt),
    // NOTE: MemoryError needs Diagnostic attributes with help text - restore at end of refactor
    #[error(transparent)]
    MemoryError(MemoryError),
}

impl OperationError {
    pub fn merkle_path_verification_failed(
        value: Word,
        index: Felt,
        root: Word,
        err_code: Felt,
        err_msg: Option<Arc<str>>,
    ) -> Self {
        Self::MerklePathVerificationFailed { value, index, root, err_code, err_msg }
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
    FailedMemoryRead(#[source] MemoryError),
    #[error("failed to decode instruction")]
    FailedDecodeInstruction,
    #[error("failed to read from the wiring bus")]
    FailedWireBusRead,
    #[error("num of wires must be less than 2^30 but was {0}")]
    TooManyWires(u64),
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
    ($mast_forest:expr, $node:expr, $host:expr) => {
        $crate::errors::ErrorContextImpl::new($mast_forest, $node, $host)
    };
    ($mast_forest:expr, $node:expr, $host:expr, $op_idx:expr) => {
        $crate::errors::ErrorContextImpl::new_with_op_idx($mast_forest, $node, $host, $op_idx)
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
    ($mast_forest:expr, $node:expr, $host:expr) => {{ () }};
    ($mast_forest:expr, $node:expr, $host:expr, $op_idx:expr) => {{ () }};
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
    #[allow(dead_code)]
    pub fn new(
        mast_forest: &MastForest,
        node: &impl MastNodeErrorContext,
        host: &impl BaseHost,
    ) -> Self {
        let (label, source_file) =
            Self::precalc_label_and_source_file(None, mast_forest, node, host);
        Self { label, source_file }
    }

    #[allow(dead_code)]
    pub fn new_with_op_idx(
        mast_forest: &MastForest,
        node: &impl MastNodeErrorContext,
        host: &impl BaseHost,
        op_idx: usize,
    ) -> Self {
        let op_idx = op_idx.into();
        let (label, source_file) =
            Self::precalc_label_and_source_file(op_idx, mast_forest, node, host);
        Self { label, source_file }
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
