// Allow unused assignments - required by miette::Diagnostic derive macro
#![allow(unused_assignments)]

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
    #[error("proof generation failed")]
    ProverError(#[source] ProverError),
    #[error(transparent)]
    MemoryError(MemoryError),
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
    #[error("failed to read callee hash for dynamic {}", if *.is_dyncall { "call" } else { "execution" })]
    DynCalleeRead {
        #[source]
        err: MemoryError,
        is_dyncall: bool,
    },
    #[error("failed to initialise frame pointer for dynamic {}", if *.is_dyncall { "call" } else { "execution" })]
    DynFrameInit {
        #[source]
        err: MemoryError,
        is_dyncall: bool,
    },
    #[error(
        "dynamic {} into callee with root {hex} failed",
        if *.is_dyncall { "call" } else { "execution" },
        hex = .callee.to_hex()
    )]
    DynReturn {
        callee: Word,
        #[source]
        err: Box<OperationError>,
        is_dyncall: bool,
    },
    #[error("procedure with root {hex} not found in any MAST forest", hex = .callee.to_hex())]
    DynForestNotFound {
        callee: Word,
        is_dyncall: bool,
    },
    #[error("MAST forest for procedure {hex} is malformed (no matching root)", hex = .callee.to_hex())]
    DynMalformedForest {
        callee: Word,
        is_dyncall: bool,
    },
    #[error(
        "invalid stack depth on return from dynamic {}: expected {MIN_STACK_DEPTH}, got {actual}",
        if *.is_dyncall { "call" } else { "execution" }
    )]
    DynInvalidStackDepthOnReturn {
        callee: Word,
        actual: usize,
        is_dyncall: bool,
    },
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
    #[error("failed to execute the program for internal reason: {reason}")]
    FailedToExecuteProgram { reason: &'static str },
    #[error("division by zero at clock cycle {clk}")]
    DivideByZero { clk: RowIndex },
    #[error(
        "when returning from a call or dyncall, stack depth must be {MIN_STACK_DEPTH}, but was {depth}"
    )]
    // TODO: restore label "when returning from this call site"
    InvalidStackDepthOnReturn { depth: usize },
    #[error("exceeded the allowed number of max cycles {max_cycles}")]
    CycleLimitExceeded { max_cycles: u32 },
    #[error("attempted to calculate integer logarithm with zero argument at clock cycle {clk}")]
    LogArgumentZero { clk: RowIndex },
    #[error("malformed signature key: {key_type}")]
    // TODO: restore help "the secret key associated with the provided public key is malformed"
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
    // TODO: restore help "this could happen either when first entering the loop, or any subsequent
    // iteration"
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
    #[error("failed to execute arithmetic circuit evaluation operation: {error}")]
    // TODO: restore label "this call failed"
    AceChipError {
        #[source]
        error: AceError,
    },
    #[error("FRI domain segment value cannot exceed 3, but was {0}")]
    InvalidFriDomainSegment(u64),
    #[error("degree-respecting projection is inconsistent: expected {0} but was {1}")]
    InvalidFriLayerFolding(QuadFelt, QuadFelt),
    #[error(transparent)]
    MemoryError { err: MemoryError },
}

impl OperationError {
    pub fn advice_error(err: AdviceError, clk: RowIndex) -> Self {
        Self::AdviceError { clk, err }
    }

    pub fn divide_by_zero(clk: RowIndex) -> Self {
        Self::DivideByZero { clk }
    }

    pub fn dynamic_node_not_found(digest: Word) -> Self {
        Self::DynamicNodeNotFound { digest }
    }

    pub fn dyn_callee_read(err: MemoryError, is_dyncall: bool) -> Self {
        Self::DynCalleeRead { err, is_dyncall }
    }

    pub fn dyn_frame_init(err: MemoryError, is_dyncall: bool) -> Self {
        Self::DynFrameInit { err, is_dyncall }
    }

    pub fn dyn_return(callee: Word, err: OperationError, is_dyncall: bool) -> Self {
        Self::DynReturn { callee, err: Box::new(err), is_dyncall }
    }

    pub fn dyn_forest_not_found(callee: Word, is_dyncall: bool) -> Self {
        Self::DynForestNotFound { callee, is_dyncall }
    }

    pub fn dyn_malformed_forest(callee: Word, is_dyncall: bool) -> Self {
        Self::DynMalformedForest { callee, is_dyncall }
    }

    pub fn dyn_invalid_stack_depth_on_return(callee: Word, actual: usize, is_dyncall: bool) -> Self {
        Self::DynInvalidStackDepthOnReturn { callee, actual, is_dyncall }
    }

    pub fn memory_error(err: MemoryError) -> Self {
        Self::MemoryError { err }
    }

    pub fn event_error(
        error: EventError,
        event_id: EventId,
        event_name: Option<EventName>,
    ) -> Self {
        Self::EventError { event_id, event_name, error }
    }

    pub fn failed_assertion(clk: RowIndex, err_code: Felt, err_msg: Option<Arc<str>>) -> Self {
        Self::FailedAssertion { clk, err_code, err_msg }
    }

    pub fn cycle_limit_exceeded(max_cycles: u32) -> Self {
        Self::CycleLimitExceeded { max_cycles }
    }

    pub fn failed_to_execute_program(reason: &'static str) -> Self {
        Self::FailedToExecuteProgram { reason }
    }

    pub fn invalid_stack_depth_on_return(depth: usize) -> Self {
        Self::InvalidStackDepthOnReturn { depth }
    }

    pub fn log_argument_zero(clk: RowIndex) -> Self {
        Self::LogArgumentZero { clk }
    }

    pub fn malformed_mast_forest_in_host(root_digest: Word) -> Self {
        Self::MalformedMastForestInHost { root_digest }
    }

    pub fn malformed_signature_key(key_type: &'static str) -> Self {
        Self::MalformedSignatureKey { key_type }
    }

    pub fn merkle_path_verification_failed(
        value: Word,
        index: Felt,
        root: Word,
        err_code: Felt,
        err_msg: Option<Arc<str>>,
    ) -> Self {
        Self::MerklePathVerificationFailed { value, index, root, err_code, err_msg }
    }

    pub fn no_mast_forest_with_procedure(root_digest: Word) -> Self {
        Self::NoMastForestWithProcedure { root_digest }
    }

    pub fn not_binary_value_if(value: Felt) -> Self {
        Self::NotBinaryValueIf { value }
    }

    pub fn not_binary_value_op(value: Felt) -> Self {
        Self::NotBinaryValueOp { value }
    }

    pub fn not_binary_value_loop(value: Felt) -> Self {
        Self::NotBinaryValueLoop { value }
    }

    pub fn not_u32_value(value: Felt, err_code: Felt) -> Self {
        Self::NotU32Values { values: vec![value], err_code }
    }

    pub fn not_u32_values(values: Vec<Felt>, err_code: Felt) -> Self {
        Self::NotU32Values { values, err_code }
    }

    pub fn input_not_u32(clk: RowIndex, input: u64) -> Self {
        Self::NotU32StackValue { clk, input }
    }

    pub fn smt_node_not_found(node: Word) -> Self {
        Self::SmtNodeNotFound { node }
    }

    pub fn smt_node_preimage_not_valid(node: Word, preimage_len: usize) -> Self {
        Self::SmtNodePreImageNotValid { node, preimage_len }
    }

    pub fn syscall_target_not_in_kernel(proc_root: Word) -> Self {
        Self::SyscallTargetNotInKernel { proc_root }
    }

    pub fn failed_arithmetic_evaluation(error: AceError) -> Self {
        Self::AceChipError { error }
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
