mod abi_types;
mod breakpoint;
mod calltrace;
mod memory;
mod native_ptr;
mod stacktrace;
mod variables;

#[cfg(feature = "dap")]
pub(crate) use self::breakpoint::{procedure_matches, procedure_pattern};
#[cfg(feature = "std")]
pub use self::stacktrace::{resolve_location_from_filesystem, resolve_source_path};
pub use self::{
    abi_types::{TypedProcedure, format_value},
    breakpoint::{Breakpoint, BreakpointType, OperationMatcher},
    calltrace::{CallFrameRecord, CallTrace, TracedArg},
    memory::{FormatType, MemoryMode, ReadMemoryExpr},
    native_ptr::NativePtr,
    stacktrace::{
        CallFrame, CallStack, ControlFlowOp, CurrentFrame, FrameTransition, InlineCallFrame,
        InvocationId, LogicalFrameKind, LogicalStackFrame, OpDetail, RecoveredCallStack,
        ResolvedLocation, ReturnTarget, StackTrace, StepInfo, inline_frames_for_operation,
        is_internal_source_uri, resolve_source_file_for_location,
    },
    variables::{
        DebugVarSnapshot, DebugVarTracker, ResolvedDebugVariable, resolve_typed_variable_values,
        resolve_variable_value, resolve_variable_values, snapshot_transient_debug_values,
    },
};
pub(crate) use self::{
    abi_types::{return_felt_count, value_felt_count},
    calltrace::CallTraceRecorder,
};
