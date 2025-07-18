use alloc::{
    boxed::Box,
    string::{String, ToString},
    sync::Arc,
};
use core::{
    error::Error,
    fmt::{self, Display, Formatter},
    ops::Deref,
};

use miden_air::RowIndex;
use miden_core::{
    Felt, QuadFelt, Word,
    mast::{DecoratorId, MastForest, MastNodeExt, MastNodeId},
    stack::MIN_STACK_DEPTH,
    utils::to_hex,
};
use miden_debug_types::{SourceFile, SourceManager, SourceSpan};
use miden_utils_diagnostics::{Diagnostic, LabeledSpan, Severity, SourceCode, miette};
use winter_prover::ProverError;

use crate::{
    EventError, MemoryError,
    host::advice::AdviceError,
    system::{FMP_MAX, FMP_MIN},
};
// EXEC ERROR TRAIT
// ================================================================================================

/// This trait defines the contract for any error that can be part of an ExecutionError.
/// It's responsible for providing the specific text for its own label.
pub trait ExecErrorTrait: Diagnostic + Send + Sync + 'static + Error {
    fn custom_label(&self) -> Option<String> {
        None
    }
}

// WRAPPED EXECUTION ERROR
// ================================================================================================

/// A wrapper around an execution error that provides context information.
#[derive(Debug)]
pub struct WrappedExecutionError {
    label: SourceSpan,
    source_file: Option<Arc<SourceFile>>,
    clk: Option<RowIndex>,
    pub err: Box<dyn ExecErrorTrait>,
}

impl WrappedExecutionError {
    pub fn new(err: impl Into<Box<dyn ExecErrorTrait>>) -> Self {
        Self {
            label: Default::default(),
            source_file: None,
            clk: None,
            err: err.into(),
        }
    }

    pub fn with_context(mut self, err_ctx: &impl ErrorContext) -> Self {
        let (label, source_file) = err_ctx.label_and_source_file();
        self.label = label;
        self.source_file = source_file;
        self
    }

    pub fn with_clk(mut self, clk: impl Into<RowIndex>) -> Self {
        self.clk = Some(clk.into());
        self
    }
}

impl Display for WrappedExecutionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if let Some(clk) = self.clk {
            write!(f, "execution error at clock cycle {clk}")
        } else {
            write!(f, "execution error")
        }
    }
}

// Manual `Error` implementation to correctly expose the source.
impl Error for WrappedExecutionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.err.as_ref())
    }
}

// Custom miette implementation, mainly to forward the label from the inner error.
impl Diagnostic for WrappedExecutionError {
    fn code<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        self.err.code()
    }

    fn severity(&self) -> Option<Severity> {
        self.err.severity()
    }

    fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        self.err.help()
    }

    fn url<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        self.err.url()
    }

    fn source_code(&self) -> Option<&dyn SourceCode> {
        self.source_file.as_ref().map(|src| src.deref() as &dyn SourceCode)
    }

    /// Custom implementation allowing wrapped errors to define their own labels.
    ///
    /// This is necessary since the `#[label]` attribute can only be applied to the
    /// `span` field, which is in the wrapper.
    fn labels(&self) -> Option<Box<dyn Iterator<Item = LabeledSpan> + '_>> {
        // Use the trait method to get the label text, no downcasting needed here.
        self.err.custom_label().map(|text| {
            let labeled_span = LabeledSpan::new_with_span(Some(text), self.label);
            Box::new([labeled_span].into_iter()) as Box<dyn Iterator<Item = _>>
        })
    }

    fn related<'a>(&'a self) -> Option<Box<dyn Iterator<Item = &'a dyn Diagnostic> + 'a>> {
        self.err.related()
    }

    fn diagnostic_source(&self) -> Option<&(dyn Diagnostic)> {
        self.err.diagnostic_source()
    }
}

impl AsRef<dyn Diagnostic> for WrappedExecutionError {
    fn as_ref(&self) -> &(dyn Diagnostic + 'static) {
        self
    }
}

// EXECUTION ERROR
// ================================================================================================

#[derive(Debug, thiserror::Error, Diagnostic)]
pub enum ExecutionError {
    #[error("advice provider error")]
    #[diagnostic()]
    AdviceError(
        #[source]
        #[diagnostic_source]
        AdviceError,
    ),
    /// This error is caught by the assembler, so we don't need diagnostics here.
    #[error("illegal use of instruction {0} while inside a syscall")]
    CallInSyscall(&'static str),
    /// This error is caught by the assembler, so we don't need diagnostics here.
    #[error("instruction `caller` used outside of kernel context")]
    CallerNotInSyscall,
    #[error("external node with mast root {0} resolved to an external node")]
    CircularExternalNode(Word),
    #[error("exceeded the allowed number of max cycles {0}")]
    CycleLimitExceeded(u32),
    #[error("decorator id {0} does not exist in MAST forest")]
    DecoratorNotFoundInForest(DecoratorId),
    #[error("division by zero")]
    DivideByZero,
    #[error("failed to execute the dynamic code block provided by the stack with root {hex}; the block could not be found",
      hex = .0.to_hex()
    )]
    DynamicNodeNotFound(Word),
    #[error("error during processing of event with id {event_id} in on_event handler")]
    EventError {
        event_id: u32,
        #[source]
        error: EventError,
    },
    #[error("attempted to add event handler with previously inserted id: {0}")]
    DuplicateEventHandler(u32),
    #[error("assertion failed with error {}",
      match err_msg {
        Some(msg) => format!("message: {msg}"),
        None => format!("code: {err_code}"),
      }
    )]
    FailedAssertion {
        err_code: Felt,
        err_msg: Option<Arc<str>>,
    },
    #[error("failed to execute the program for internal reason: {0}")]
    FailedToExecuteProgram(&'static str),
    #[error(
        "Updating FMP register from {0} to {1} failed because {1} is outside of {FMP_MIN}..{FMP_MAX}"
    )]
    InvalidFmpValue(Felt, Felt),
    #[error("FRI domain segment value cannot exceed 3, but was {0}")]
    InvalidFriDomainSegment(u64),
    #[error("degree-respecting projection is inconsistent: expected {0} but was {1}")]
    InvalidFriLayerFolding(QuadFelt, QuadFelt),
    #[error(
        "when returning from a call or dyncall, stack depth must be {MIN_STACK_DEPTH}, but was {0}"
    )]
    InvalidStackDepthOnReturn(usize),
    #[error("attempted to calculate integer logarithm with zero argument")]
    LogArgumentZero,
    #[error("malformed signature key: {key_type}")]
    #[diagnostic(help("the secret key associated with the provided public key is malformed"))]
    MalformedSignatureKey { key_type: &'static str },
    #[error("MAST forest in host indexed by procedure root {0} doesn't contain that root")]
    MalformedMastForestInHost(Word),
    #[error("node id {node_id} does not exist in MAST forest")]
    MastNodeNotFoundInForest { node_id: MastNodeId },
    #[error(transparent)]
    #[diagnostic(transparent)]
    MemoryError(MemoryError),
    #[error("no MAST forest contains the procedure with root digest {0}")]
    NoMastForestWithProcedure(Word),
    #[error("merkle path verification failed for value {value} at index {index} in the Merkle tree with root {root} (error {err})",
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
    #[error("if statement expected a binary value on top of the stack, but got {0}")]
    NotBinaryValueIf(Felt),
    #[error("operation expected a binary value, but got {0}")]
    NotBinaryValueOp(Felt),
    #[error("loop condition must be a binary value, but got {0}")]
    #[diagnostic(help(
        "this could happen either when first entering the loop, or any subsequent iteration"
    ))]
    NotBinaryValueLoop(Felt),
    #[error("operation expected a u32 value, but got {value}")]
    // #[error("operation expected a u32 value, but got {value} (error code: {err_code})")]
    NotU32Value { value: Felt, err_code: Option<Felt> },
    #[error("stack should have at most {MIN_STACK_DEPTH} elements at the end of program execution, but had {} elements", MIN_STACK_DEPTH + .0)]
    OutputStackOverflow(usize),
    #[error("a program has already been executed in this process")]
    ProgramAlreadyExecuted,
    #[error("proof generation failed")]
    ProverError(#[source] ProverError),
    #[error("smt node {node_hex} not found", node_hex = to_hex(.0.as_bytes()))]
    SmtNodeNotFound(Word),
    #[error("expected pre-image length of node {node_hex} to be a multiple of 8 but was {preimage_len}",
      node_hex = to_hex(node.as_bytes()),
    )]
    SmtNodePreImageNotValid { node: Word, preimage_len: usize },
    #[error("syscall failed: procedure with root {hex} was not found in the kernel",
      hex = to_hex(.0.as_bytes())
    )]
    SyscallTargetNotInKernel(Word),
    #[error("failed to execute arithmetic circuit evaluation operation: {0}")]
    AceChipError(AceError),
}

impl ExecutionError {
    pub fn advice_error(err: AdviceError) -> ExecutionError {
        ExecutionError::AdviceError(err)
    }

    pub fn divide_by_zero() -> Self {
        Self::DivideByZero
    }

    pub fn input_not_u32(value: u64) -> Self {
        Self::NotU32Value { value: Felt::new(value), err_code: None }
    }

    pub fn dynamic_node_not_found(digest: Word) -> Self {
        Self::DynamicNodeNotFound(digest)
    }

    pub fn event_error(error: EventError, event_id: u32) -> Self {
        Self::EventError { event_id, error }
    }

    pub fn failed_assertion(err_code: Felt, err_msg: Option<Arc<str>>) -> Self {
        Self::FailedAssertion { err_code, err_msg }
    }

    pub fn invalid_stack_depth_on_return(depth: usize) -> Self {
        Self::InvalidStackDepthOnReturn(depth)
    }

    pub fn log_argument_zero() -> Self {
        Self::LogArgumentZero
    }

    pub fn malfored_mast_forest_in_host(root_digest: Word) -> Self {
        Self::MalformedMastForestInHost(root_digest)
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
        Self::NoMastForestWithProcedure(root_digest)
    }

    pub fn not_binary_value_if(value: Felt) -> Self {
        Self::NotBinaryValueIf(value)
    }

    pub fn not_binary_value_op(value: Felt) -> Self {
        Self::NotBinaryValueOp(value)
    }

    pub fn not_binary_value_loop(value: Felt) -> Self {
        Self::NotBinaryValueLoop(value)
    }

    pub fn not_u32_value(value: Felt, err_code: Felt) -> Self {
        Self::NotU32Value { value, err_code: Some(err_code) }
    }

    pub fn smt_node_not_found(node: Word) -> Self {
        Self::SmtNodeNotFound(node)
    }

    pub fn smt_node_preimage_not_valid(node: Word, preimage_len: usize) -> Self {
        Self::SmtNodePreImageNotValid { node, preimage_len }
    }

    pub fn syscall_target_not_in_kernel(proc_root: Word) -> Self {
        Self::SyscallTargetNotInKernel(proc_root)
    }

    pub fn failed_arithmetic_evaluation(error: AceError) -> Self {
        Self::AceChipError(error)
    }
}

impl ExecErrorTrait for ExecutionError {
    fn custom_label(&self) -> Option<String> {
        match self {
            Self::NotBinaryValueIf(value) => {
                Some(format!("expected a binary value, but got {value}"))
            },
            Self::NotBinaryValueOp(value) => {
                Some(format!("expected a binary value, but got {value}"))
            },
            Self::NotBinaryValueLoop(value) => {
                Some(format!("expected a binary value, but got {value}"))
            },
            Self::NotU32Value { value, .. } => {
                Some(format!("expected a u32 value, but got {value}"))
            },
            Self::InvalidStackDepthOnReturn { .. } => {
                Some("when returning from this call site".to_string())
            },
            Self::AceChipError { .. } => Some("this call failed".to_string()),
            _ => None,
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
    ($mast_forest:expr, $node:expr, $source_manager:expr) => {
        $crate::errors::ErrorContextImpl::new($mast_forest, $node, $source_manager)
    };
    ($mast_forest:expr, $node:expr, $source_manager:expr, $op_idx:expr) => {
        $crate::errors::ErrorContextImpl::new_with_op_idx($mast_forest, $node, $source_manager, $op_idx)
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
    ($mast_forest:expr, $node:expr, $source_manager:expr) => {{ () }};
    ($mast_forest:expr, $node:expr, $source_manager:expr, $op_idx:expr) => {{ () }};
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
#[derive(Debug)]
pub struct ErrorContextImpl<'a, N: MastNodeExt> {
    mast_forest: &'a MastForest,
    node: &'a N,
    source_manager: Arc<dyn SourceManager>,
    op_idx: Option<usize>,
}

impl<'a, N: MastNodeExt> ErrorContextImpl<'a, N> {
    #[allow(dead_code)]
    pub fn new(
        mast_forest: &'a MastForest,
        node: &'a N,
        source_manager: Arc<dyn SourceManager>,
    ) -> Self {
        Self {
            mast_forest,
            node,
            source_manager,
            op_idx: None,
        }
    }

    #[allow(dead_code)]
    pub fn new_with_op_idx(
        mast_forest: &'a MastForest,
        node: &'a N,
        source_manager: Arc<dyn SourceManager>,
        op_idx: usize,
    ) -> Self {
        Self {
            mast_forest,
            node,
            source_manager,
            op_idx: Some(op_idx),
        }
    }

    pub fn label_and_source_file(&self) -> (SourceSpan, Option<Arc<SourceFile>>) {
        self.node
            .get_assembly_op(self.mast_forest, self.op_idx)
            .and_then(|assembly_op| assembly_op.location())
            .map_or_else(
                || (SourceSpan::UNKNOWN, None),
                |location| {
                    (
                        self.source_manager.location_to_span(location.clone()).unwrap_or_default(),
                        self.source_manager.get_by_uri(&location.uri),
                    )
                },
            )
    }
}

impl<'a, N: MastNodeExt> ErrorContext for ErrorContextImpl<'a, N> {
    fn label_and_source_file(&self) -> (SourceSpan, Option<Arc<SourceFile>>) {
        self.label_and_source_file()
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
