// Allow unused assignments - required by miette::Diagnostic derive macro
#![allow(unused_assignments)]

use alloc::{boxed::Box, string::String, sync::Arc, vec::Vec};
use core::fmt;

use miden_air_definitions::vm::trace::chiplets::hasher::MAX_MERKLE_DEPTH;
use miden_core::{deferred::PrecompileError, program::MIN_STACK_DEPTH};
use miden_debug_types::{Location, SourceFile, SourceSpan};
use miden_mast_package::{
    PackageDebugInfoError,
    debug_info::{DebugSourceNodeId, PackageDebugInfo},
};
use miden_utils_diagnostics::{Diagnostic, miette};

use crate::{
    BaseHost, ContextId, Felt, Word,
    advice::AdviceError,
    event::{EventError, EventId, EventName},
    utils::to_hex,
};

// EXECUTION ERROR
// ================================================================================================

/// A typed execution failure with source diagnostics resolved at its execution boundary.
///
/// Low-level operations propagate [`ProcessorError`] or a narrower domain error. The boundary
/// that owns the failing source occurrence calls [`ProcessorError::with_context`] once. Errors
/// outside instruction execution, such as initialization and output validation, can be converted
/// directly without source diagnostics.
#[derive(Debug, Diagnostic)]
pub struct ExecutionError {
    kind: ProcessorError,
    #[label]
    source_span: Option<SourceSpan>,
    #[source_code]
    source_file: Option<Arc<SourceFile>>,
}

impl ExecutionError {
    /// Returns the classified failure independently of its source diagnostics.
    pub fn kind(&self) -> &ProcessorError {
        &self.kind
    }

    /// Consumes this error and returns its classified failure.
    pub fn into_kind(self) -> ProcessorError {
        self.kind
    }

    /// Returns the source span of the failing instruction or control-flow node, when known.
    pub fn source_span(&self) -> Option<SourceSpan> {
        self.source_span
    }

    /// Returns the source file supplied by the host, when available.
    pub fn source_file(&self) -> Option<&Arc<SourceFile>> {
        self.source_file.as_ref()
    }
}

impl fmt::Display for ExecutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.kind, f)
    }
}

impl core::error::Error for ExecutionError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        // This wrapper adds diagnostics, not another causal layer with the same error message.
        core::error::Error::source(&self.kind)
    }
}

impl AsRef<dyn Diagnostic> for ExecutionError {
    fn as_ref(&self) -> &(dyn Diagnostic + 'static) {
        self
    }
}

/// A context-free failure produced while initializing or running the processor.
///
/// `From` conversions preserve typed causes while allowing ordinary `?` propagation. Source spans,
/// files, and package error messages are resolved only when the failing execution boundary is
/// known.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ProcessorError {
    #[error("failed to execute arithmetic circuit evaluation operation: {0}")]
    Ace(#[from] AceError),
    #[error(transparent)]
    Advice(#[from] AdviceError),
    #[error("exceeded the allowed number of max cycles {0}")]
    CycleLimitExceeded(u32),
    #[error("error during processing of event {}", match event_name {
        Some(name) => format!("'{name}' (ID: {event_id})"),
        None => format!("with ID: {event_id}"),
    })]
    Event {
        event_id: EventId,
        event_name: Option<EventName>,
        #[source]
        source: EventError,
    },
    /// Failed to load a MAST forest from the host.
    #[error("failed to load MAST forest for procedure with root digest {root_digest}: {source}")]
    MastForestLoad {
        root_digest: Word,
        #[source]
        source: crate::MastForestLoadError,
    },
    #[error(transparent)]
    Deferred(#[from] PrecompileError),
    #[error("failed to execute the program for internal reason: {0}")]
    Internal(&'static str),
    #[error("operand stack depth {depth} exceeds the maximum of {max}")]
    StackDepthLimitExceeded { depth: usize, max: usize },
    #[error(transparent)]
    Memory(#[from] MemoryError),
    #[error(transparent)]
    Operation(#[from] OperationError),
    #[error("stack should have at most {MIN_STACK_DEPTH} elements at the end of program execution, but had {} elements", MIN_STACK_DEPTH + .0)]
    OutputStackOverflow(usize),
    #[error("procedure with root digest {root_digest} could not be found")]
    ProcedureNotFound { root_digest: Word },
    #[error(transparent)]
    PackageDebugInfo(#[from] Arc<PackageDebugInfoError>),
}

impl ProcessorError {
    /// Resolves diagnostic context once, while the failing source occurrence is still available.
    ///
    /// The context must belong to the package containing that occurrence. Package assertion
    /// messages are resolved even if source locations or source files are unavailable. For a
    /// control-flow node, pass `None` for `op_idx` to use its first assembly operation.
    pub fn with_context(
        self,
        context: Option<PackageSourceDebugContext<'_>>,
        host: &(dyn BaseHost + '_),
        op_idx: Option<usize>,
    ) -> ExecutionError {
        let mut error = ExecutionError::from(self);
        if let Some(context) = context {
            if let Self::Operation(err) = error.kind {
                error.kind = Self::Operation(err.with_package_debug_info(context.debug_info));
            }
            if let Some(location) = context.assembly_location(op_idx) {
                let (span, source_file) = host.get_label_and_source_file(&location);
                error.source_span = (span != SourceSpan::UNKNOWN).then_some(span);
                error.source_file = source_file;
            }
        }
        error
    }
}

impl From<ProcessorError> for ExecutionError {
    fn from(kind: ProcessorError) -> Self {
        Self {
            kind,
            source_span: None,
            source_file: None,
        }
    }
}

impl From<AdviceError> for ExecutionError {
    fn from(error: AdviceError) -> Self {
        ProcessorError::Advice(error).into()
    }
}

impl From<PrecompileError> for ExecutionError {
    fn from(error: PrecompileError) -> Self {
        ProcessorError::Deferred(error).into()
    }
}

// ACE ERROR
// ================================================================================================

#[derive(Debug, thiserror::Error)]
#[error("ace circuit evaluation failed: {0}")]
pub struct AceError(pub String);

// HOST ERROR
// ================================================================================================

/// Error type for host-related operations.
#[derive(Debug, thiserror::Error, Diagnostic)]
pub enum HostError {
    #[error("attempted to add event handler for '{event}' (already registered)")]
    DuplicateEventHandler { event: EventName },
    #[error(
        "attempted to add event handler for '{event}' (reserved '{namespace}' namespace)",
        namespace = EventName::RESERVED_NAMESPACE
    )]
    ReservedEventNamespace { event: EventName },
    #[error("attempted to add event handler with an empty event name")]
    EmptyEventName,
}

// MEMORY ERROR
// ================================================================================================

/// Lightweight error type for memory operations.
///
/// This enum captures error conditions without expensive context information (no source location,
/// no file references). Execution boundaries add source diagnostics after propagation through
/// [`ProcessorError`].
#[derive(Debug, thiserror::Error)]
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
    /// Configured by [`crate::ExecutionOptions::with_max_memory_elements`].
    #[error(
        "writing to memory address {addr} in context {ctx} would exceed the maximum number of memory elements {max}"
    )]
    MemoryElementLimitExceeded { ctx: ContextId, addr: u32, max: usize },
}

// OPERATION ERROR
// ================================================================================================

/// A failure specific to an operation, independent of source diagnostics.
///
/// Propagate it directly from narrow helpers, or through [`ProcessorError`] when an operation
/// combines multiple failure sources. The execution boundary resolves package messages and source
/// locations once the failing source occurrence is known.
#[derive(Debug, Clone, thiserror::Error)]
pub enum OperationError {
    #[error("external node with mast root {0} resolved to an external node")]
    CircularExternalNode(Word),
    #[error("clear_deferred requires root context, but was executed in context {ctx}")]
    ClearDeferredOutsideRootContext { ctx: ContextId },
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
        "Horner evaluation point at memory address {addr} in context {ctx} must be encoded as [alpha0, alpha1, 0, 0]"
    )]
    InvalidHornerEvaluationPointWord { ctx: ContextId, addr: u64 },
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
    #[error("Merkle tree depth must be in the range 1..={MAX_MERKLE_DEPTH}, but was {depth}")]
    MerkleDepthOutOfRange { depth: Felt },
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

// SOURCE CONTEXT
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
    /// Creates a package debug context when source location metadata may be unavailable.
    pub fn new(
        debug_info: &'a PackageDebugInfo,
        source_node_id: Option<DebugSourceNodeId>,
    ) -> Self {
        Self { debug_info, source_node_id }
    }

    /// Returns source location metadata for `op_idx`, if present.
    ///
    /// If `op_idx` is absent, this falls back to the first operation row for the source occurrence.
    pub fn assembly_location(&self, op_idx: Option<usize>) -> Option<Location> {
        let source_node_id = self.source_node_id?;
        let assembly_op = match op_idx {
            Some(op_idx) => u32::try_from(op_idx)
                .ok()
                .and_then(|op_idx| self.debug_info.asm_op_for_operation(source_node_id, op_idx)),
            None => self.debug_info.first_asm_op_for_source_node(source_node_id),
        }?;

        assembly_op
            .location_idx
            .into_option()
            .and_then(|idx| self.debug_info.get_location(idx))
    }
}

#[cfg(test)]
mod error_assertions {
    use alloc::sync::Arc;

    use miden_core::mast::MastNodeId;
    use miden_debug_types::{ByteIndex, SourceId, Uri};
    use miden_mast_package::debug_info::{
        DebugSourceAsmOp, DebugSourceNode, PackageDebugInfoBuilder,
    };

    use super::*;

    /// Asserts at compile time that the passed error has Send + Sync + 'static bounds.
    fn _assert_error_is_send_sync_static<E: core::error::Error + Send + Sync + 'static>(_: E) {}

    fn _assert_execution_error_bounds(err: ExecutionError) {
        _assert_error_is_send_sync_static(err);
    }

    fn debug_asm_op(
        builder: &mut PackageDebugInfoBuilder,
        op_idx: u32,
        location: Option<Location>,
        context_name: &str,
        op_name: &str,
    ) -> DebugSourceAsmOp {
        DebugSourceAsmOp::new(
            op_idx,
            location.map(|location| builder.add_location(location)),
            builder.add_string(context_name),
            builder.add_string(op_name),
            1,
        )
    }

    fn debug_source_node(exec_node: u32, asm_ops: Vec<DebugSourceAsmOp>) -> DebugSourceNode {
        let op_end = asm_ops.iter().map(|row| row.op_idx + 1).max().unwrap_or(1);
        DebugSourceNode {
            exec_node: MastNodeId::from(exec_node),
            children: Vec::new(),
            op_start: 0,
            op_end,
            asm_ops,
            debug_vars: Vec::new(),
            inline_calls: Vec::new(),
        }
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
        let mut builder = PackageDebugInfoBuilder::default();
        let source_a_op = debug_asm_op(&mut builder, 0, Some(location_a), "first", "add");
        let _source_a = builder.add_node(debug_source_node(0, vec![source_a_op])).unwrap();
        let source_b_later_op =
            debug_asm_op(&mut builder, 2, Some(later_location_b), "second_later", "mul");
        let source_b_op = debug_asm_op(&mut builder, 0, Some(location_b.clone()), "second", "add");
        let source_b = builder
            .add_node(debug_source_node(1, vec![source_b_later_op, source_b_op]))
            .unwrap();
        let debug_info = *builder.build();
        let host = RecordingHost {
            expected_location: location_b,
            returned_span: SourceSpan::new(SourceId::new(7), 20u32..24),
        };
        let context = PackageSourceDebugContext::new(&debug_info, Some(source_b));

        assert_eq!(context.assembly_location(None), Some(host.expected_location.clone()));

        let err = ProcessorError::Operation(OperationError::DivideByZero).with_context(
            Some(context),
            &host,
            Some(0),
        );

        assert_eq!(err.source_span(), Some(host.returned_span));
        assert!(err.source_file().is_none());
        assert!(matches!(err.kind(), ProcessorError::Operation(OperationError::DivideByZero)));
        assert_eq!(err.labels().unwrap().count(), 1);
    }

    #[test]
    fn package_source_context_without_location_has_no_label() {
        let mut builder = PackageDebugInfoBuilder::default();
        let asm_op = debug_asm_op(&mut builder, 0, None, "missing_location", "add");
        let source_node_id = builder.add_node(debug_source_node(0, vec![asm_op])).unwrap();
        let debug_info = *builder.build();
        let host = RecordingHost {
            expected_location: Location::new(
                Uri::new("file://unused.masm"),
                ByteIndex::new(0),
                ByteIndex::new(0),
            ),
            returned_span: SourceSpan::new(SourceId::new(7), 20u32..24),
        };
        let context = PackageSourceDebugContext::new(&debug_info, Some(source_node_id));

        let err = ProcessorError::Advice(AdviceError::StackReadFailed).with_context(
            Some(context),
            &host,
            Some(0),
        );

        assert!(err.source_span().is_none());
        assert!(err.source_file().is_none());
        assert!(matches!(err.kind(), ProcessorError::Advice(AdviceError::StackReadFailed)));
        assert_eq!(err.labels().unwrap().count(), 0);
    }

    #[test]
    fn package_debug_info_without_source_node_restores_error_message() {
        let mut builder = PackageDebugInfoBuilder::default();
        assert!(builder.add_error_message(7, Arc::from("some error message")));
        let debug_info = *builder.build();
        let context = PackageSourceDebugContext::new(&debug_info, None);
        let err = ProcessorError::Operation(OperationError::FailedAssertion {
            err_code: Felt::from_u32(7),
            err_msg: None,
        })
        .with_context(
            Some(context),
            &RecordingHost {
                expected_location: Location::new(
                    Uri::new("file://unused.masm"),
                    ByteIndex::new(0),
                    ByteIndex::new(0),
                ),
                returned_span: SourceSpan::new(SourceId::new(7), 20u32..24),
            },
            Some(0),
        );

        assert!(err.source_span().is_none());
        assert!(err.source_file().is_none());
        match err.into_kind() {
            ProcessorError::Operation(OperationError::FailedAssertion { err_msg, .. }) => {
                assert_eq!(err_msg.as_deref(), Some("some error message"));
            },
            err => panic!("expected failed assertion operation error, got {err:?}"),
        }
    }

    #[test]
    fn package_debug_info_restores_merkle_path_error_message() {
        let mut builder = PackageDebugInfoBuilder::default();
        assert!(builder.add_error_message(7, Arc::from("some error message")));
        let debug_info = *builder.build();
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

    #[test]
    fn source_diagnostics_are_shared_by_failure_kinds() {
        use core::cell::Cell;

        struct CountingHost(Cell<usize>);
        impl BaseHost for CountingHost {
            fn get_label_and_source_file(
                &self,
                _location: &Location,
            ) -> (SourceSpan, Option<Arc<SourceFile>>) {
                self.0.set(self.0.get() + 1);
                (SourceSpan::new(SourceId::new(3), 4u32..8), None)
            }
        }
        let mut builder = PackageDebugInfoBuilder::default();
        let location =
            Location::new(Uri::new("file://pkg/test.masm"), ByteIndex::new(4), ByteIndex::new(8));
        let asm_op = debug_asm_op(&mut builder, 0, Some(location), "test", "add");
        let node = builder.add_node(debug_source_node(0, vec![asm_op])).unwrap();
        let debug_info = *builder.build();
        let context = PackageSourceDebugContext::new(&debug_info, Some(node));
        let host = CountingHost(Cell::new(0));
        for (index, kind) in [
            ProcessorError::Operation(OperationError::DivideByZero),
            ProcessorError::Advice(AdviceError::StackReadFailed),
            ProcessorError::Memory(MemoryError::AddressOutOfBounds { addr: u64::MAX }),
            ProcessorError::StackDepthLimitExceeded { depth: 20, max: 19 },
        ]
        .into_iter()
        .enumerate()
        {
            let error = kind.with_context(Some(context), &host, Some(0));
            assert_eq!(error.source_span(), Some(SourceSpan::new(SourceId::new(3), 4u32..8)));
            assert_eq!(error.labels().unwrap().count(), 1);
            assert_eq!(host.0.get(), index + 1);
        }
    }
}
