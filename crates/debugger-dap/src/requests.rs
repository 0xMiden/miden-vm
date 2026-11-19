use serde::Deserialize;
#[cfg(feature = "client")]
use serde::Serialize;
use serde_json::Value;

use crate::{
    errors::ServerError,
    prelude::{Response, ResponseBody},
    responses::ResponseMessage,
    types::{
        EvaluateArgumentsContext, FunctionBreakpoint, Source, SourceBreakpoint, StackFrameFormat,
        SteppingGranularity, ValueFormat, VariablesArgumentsFilter,
    },
};

#[cfg_attr(feature = "client", derive(Serialize))]
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub enum PathFormat {
    Path,
    Uri,
    #[serde(untagged)]
    Other(String),
}

/// Arguments for an Initialize request.
/// In specification: [Initialize](https://microsoft.github.io/debug-adapter-protocol/specification#Requests_Initialize)
#[cfg_attr(feature = "client", derive(Serialize))]
#[derive(Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct InitializeArguments {
    /// The ID of the client using this adapter.
    #[serde(rename = "clientID")]
    pub client_id: Option<String>,
    /// The human-readable name of the client using this adapter.
    pub client_name: Option<String>,
    /// The ID of the debug adapter.
    #[serde(rename = "adapterID")]
    pub adapter_id: String,
    /// The ISO-639 locale of the client using this adapter, e.g. en-US or de-CH.
    pub locale: Option<String>,
    /// If true all line i64s are 1-based (default).
    pub lines_start_at1: Option<bool>,
    /// If true all column i64s are 1-based (default).
    pub columns_start_at1: Option<bool>,
    /// Determines in what format paths are specified. The default is `path`, which
    /// is the native format.
    pub path_format: Option<PathFormat>,
    /// Client supports the `type` attribute for variables.
    pub supports_variable_type: Option<bool>,
    /// Client supports the paging of variables.
    pub supports_variable_paging: Option<bool>,
    /// Client supports the `runInTerminal` request.
    pub supports_run_in_terminal_request: Option<bool>,
    /// Client supports memory references.
    pub supports_memory_references: Option<bool>,
    /// Client supports progress reporting.
    pub supports_progress_reporting: Option<bool>,
    /// Client supports the `invalidated` event.
    pub supports_invalidated_event: Option<bool>,
    /// Client supports the `memory` event.
    pub supports_memory_event: Option<bool>,
    /// Client supports the `argsCanBeInterpretedByShell` attribute on the `runInTerminal` request.
    pub supports_args_can_be_interpreted_by_shell: Option<bool>,
    /// Client supports the `startDebugging` request.
    pub supports_start_debugging_request: Option<bool>,
}

/// Arguments for an SetBreakpoints request.
/// In specification: [SetBreakpoints](https://microsoft.github.io/debug-adapter-protocol/specification#Requests_Initialize)
#[cfg_attr(feature = "client", derive(Serialize))]
#[derive(Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SetBreakpointsArguments {
    /// The source location of the breakpoints, either `source.path` or
    /// `source.sourceReference` must be specified.
    pub source: Source,
    /// The code locations of the breakpoints.
    pub breakpoints: Option<Vec<SourceBreakpoint>>,
    /// Deprecated: The code locations of the breakpoints.
    #[deprecated]
    pub lines: Option<Vec<i64>>,
    /// A value of true indicates that the underlying source has been modified
    /// which results in new breakpoint locations.
    pub source_modified: Option<bool>,
}

#[cfg_attr(feature = "client", derive(Serialize))]
#[derive(Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SetFunctionBreakpointsArguments {
    /// The function names of the breakpoints.
    pub breakpoints: Vec<FunctionBreakpoint>,
}

/// Arguments for a Launch request.
#[cfg_attr(feature = "client", derive(Serialize))]
#[derive(Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LaunchRequestArguments {
    /// If true, the launch request should launch the program without enabling
    /// debugging.
    pub no_debug: Option<bool>,
    /// Arbitrary data from the previous, restarted session.
    /// The data is sent as the `restart` attribute of the `terminated` event.
    /// The client should leave the data intact.
    ///
    /// Rust-specific: this data must be a string. Server requiring storing binary data should use
    /// an encoding that is suitable for string (e.g. base85 or similar).
    #[serde(rename = "__restart")]
    pub restart_data: Option<Value>,
    /// The request may include additional implementation specific attributes.
    #[serde(flatten)]
    pub additional_data: Option<Value>,
}

/// Arguments for an Attach request.
#[cfg_attr(feature = "client", derive(Serialize))]
#[derive(Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AttachRequestArguments {
    /// Arbitrary data from the previous, restarted session.
    /// The data is sent as the `restart` attribute of the `terminated` event.
    /// The client should leave the data intact.
    #[serde(rename = "__restart")]
    pub restart_data: Option<Value>,

    /// The request may include additional implementation specific attributes.
    #[serde(flatten)]
    pub additional_data: Option<Value>,
}

/// Union of Attach and Launch arguments for the Restart request.
/// Currently the same as LaunchRequestArguments but might not be in the future.
#[derive(Deserialize, Debug, Default, Clone)]
#[cfg_attr(feature = "client", derive(Serialize))]
#[serde(rename_all = "camelCase")]
pub struct AttachOrLaunchArguments {
    /// If true, the launch request should launch the program without enabling
    /// debugging.
    pub no_debug: Option<bool>,

    /// Arbitrary data from the previous, restarted session.
    /// The data is sent as the `restart` attribute of the `terminated` event.
    /// The client should leave the data intact.
    #[serde(rename = "__restart")]
    pub restart_data: Option<Value>,

    /// The request may include additional implementation specific attributes.
    #[serde(flatten)]
    pub additional_data: Option<Value>,
}

/// Arguments for a Continue request.
#[cfg_attr(feature = "client", derive(Serialize))]
#[derive(Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ContinueArguments {
    /// Specifies the active thread. If the debug adapter supports single thread
    /// execution (see `supportsSingleThreadExecutionRequests`) and the argument
    /// `singleThread` is true, only the thread with this ID is resumed.
    pub thread_id: i64,
    /// If this flag is true, execution is resumed only for the thread with given
    /// `threadId`.
    pub single_thread: Option<bool>,
}

/// Arguments for a Disconnect request.
#[cfg_attr(feature = "client", derive(Serialize))]
#[derive(Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DisconnectArguments {
    /// A value of true indicates that this `disconnect` request is part of a
    /// restart sequence.
    pub restart: Option<bool>,
    /// Indicates whether the debuggee should be terminated when the debugger is
    /// disconnected.
    /// If unspecified, the debug adapter is free to do whatever it thinks is best.
    /// The attribute is only honored by a debug adapter if the corresponding
    /// capability `supportTerminateDebuggee` is true.
    pub terminate_debuggee: Option<bool>,
    /// Indicates whether the debuggee should stay suspended when the debugger is
    /// disconnected.
    /// If unspecified, the debuggee should resume execution.
    /// The attribute is only honored by a debug adapter if the corresponding
    /// capability `supportSuspendDebuggee` is true.
    pub suspend_debuggee: Option<bool>,
}

/// Arguments for a Evaluate request.
#[cfg_attr(feature = "client", derive(Serialize))]
#[derive(Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct EvaluateArguments {
    /// The expression to evaluate.
    pub expression: String,
    /// Evaluate the expression in the scope of this stack frame. If not specified,
    /// the expression is evaluated in the global scope.
    pub frame_id: Option<i64>,
    /// The context in which the evaluate request is used.
    /// Values:
    /// 'variables': evaluate is called from a variables view context.
    /// 'watch': evaluate is called from a watch view context.
    /// 'repl': evaluate is called from a REPL context.
    /// 'hover': evaluate is called to generate the debug hover contents.
    /// This value should only be used if the corresponding capability
    /// `supportsEvaluateForHovers` is true.
    /// 'clipboard': evaluate is called to generate clipboard contents.
    /// This value should only be used if the corresponding capability
    /// `supportsClipboardContext` is true.
    /// etc.
    pub context: Option<EvaluateArgumentsContext>,
    /// Specifies details on how to format the result.
    /// The attribute is only honored by a debug adapter if the corresponding
    /// capability `supportsValueFormattingOptions` is true.
    pub format: Option<ValueFormat>,
}

/// Arguments for a Next request.
#[cfg_attr(feature = "client", derive(Serialize))]
#[derive(Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct NextArguments {
    /// Specifies the thread for which to resume execution for one step (of the
    /// given granularity).
    pub thread_id: i64,
    /// If this flag is true, all other suspended threads are not resumed.
    pub single_thread: Option<bool>,
    /// Stepping granularity. If no granularity is specified, a granularity of
    /// `statement` is assumed.
    pub granularity: Option<SteppingGranularity>,
}

/// Arguments for a ReadMemory request.
#[derive(Deserialize, Debug, Clone)]
#[cfg_attr(feature = "client", derive(Serialize))]
#[serde(rename_all = "camelCase")]
pub struct RestartArguments {
    pub arguments: Option<AttachOrLaunchArguments>,
}

/// Arguments for a Scopes request.
#[cfg_attr(feature = "client", derive(Serialize))]
#[derive(Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ScopesArguments {
    /// Retrieve the scopes for this stackframe.
    pub frame_id: i64,
}

/// Arguments for a StackTrace request.
#[cfg_attr(feature = "client", derive(Serialize))]
#[derive(Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct StackTraceArguments {
    /// Retrieve the stacktrace for this thread.
    pub thread_id: i64,
    /// The index of the first frame to return, if omitted frames start at 0.
    pub start_frame: Option<i64>,
    /// The maximum i64 of frames to return. If levels is not specified or 0,
    /// all frames are returned.
    pub levels: Option<i64>,
    /// Specifies details on how to format the stack frames.
    /// The attribute is only honored by a debug adapter if the corresponding
    /// capability `supportsValueFormattingOptions` is true.
    pub format: Option<StackFrameFormat>,
}

/// Arguments for a StepIn request.
#[cfg_attr(feature = "client", derive(Serialize))]
#[derive(Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct StepInArguments {
    /// Specifies the thread for which to resume execution for one step-into (of
    /// the given granularity).
    pub thread_id: i64,
    /// If this flag is true, all other suspended threads are not resumed.
    pub single_thread: Option<bool>,
    /// Id of the target to step into.
    pub target_id: Option<i64>,
    /// Stepping granularity. If no granularity is specified, a granularity of
    /// `statement` is assumed.
    pub granularity: Option<SteppingGranularity>,
}

/// Arguments for a StepOut request.
#[cfg_attr(feature = "client", derive(Serialize))]
#[derive(Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct StepOutArguments {
    /// Specifies the thread for which to resume execution for one step-out (of the
    /// given granularity).
    pub thread_id: i64,
    /// If this flag is true, all other suspended threads are not resumed.
    pub single_thread: Option<bool>,
    /// Stepping granularity. If no granularity is specified, a granularity of
    /// `statement` is assumed.
    pub granularity: Option<SteppingGranularity>,
}

/// Arguments for a Variables request.
#[cfg_attr(feature = "client", derive(Serialize))]
#[derive(Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct VariablesArguments {
    /// The variable for which to retrieve its children. The `variablesReference`
    /// must have been obtained in the current suspended state.
    /// See [Lifetime of Object References](https://microsoft.github.io/debug-adapter-protocol/overview#lifetime-of-objects-references)
    /// in the Overview section of the specification for details.
    pub variables_reference: i64,
    /// Filter to limit the child variables to either named or indexed. If omitted,
    /// both types are fetched.
    /// Values: 'indexed', 'named'
    pub filter: Option<VariablesArgumentsFilter>,
    /// The index of the first variable to return, if omitted children start at 0.
    pub start: Option<i64>,
    /// The i64 of variables to return. If count is missing or 0, all variables
    /// are returned.
    pub count: Option<i64>,
    /// Specifies details on how to format the Variable values.
    /// The attribute is only honored by a debug adapter if the corresponding
    /// capability `supportsValueFormattingOptions` is true.
    pub format: Option<ValueFormat>,
}

#[cfg_attr(feature = "client", derive(Serialize))]
#[derive(Deserialize, Debug, Clone)]
#[serde(tag = "command", content = "arguments", rename_all = "camelCase")]
pub enum Command {
    /// The attach request is sent from the client to the debug adapter to attach to a debuggee that
    /// is already running.
    /// kSince attaching is debugger/runtime specific, the arguments for this request are not part
    /// of this specification.
    ///
    /// Specification: [Attach request](https://microsoft.github.io/debug-adapter-protocol/specification#Requests_Attach)
    Attach(AttachRequestArguments),
    /// This request indicates that the client has finished initialization of the debug adapter.
    /// So it is the last request in the sequence of configuration requests (which was started by
    /// the initialized event). Clients should only call this request if the corresponding
    /// capability supportsConfigurationDoneRequest is true.
    ///
    /// Specification: [ConfigurationDone](https://microsoft.github.io/debug-adapter-protocol/specification#Requests_ConfigurationDone)
    ConfigurationDone,
    /// The request resumes execution of all threads. If the debug adapter supports single thread
    /// execution (see capability `supportsSingleThreadExecutionRequests`), setting the singleThread
    /// argument to true resumes only the specified thread. If not all threads were resumed, the
    /// `allThreadsContinued` attribute of the response should be set to false.
    ///
    /// Specification: [Continue request](https://microsoft.github.io/debug-adapter-protocol/specification#Requests_Continue)
    Continue(ContinueArguments),
    /// The `disconnect` request asks the debug adapter to disconnect from the debuggee (thus ending
    /// the debug session) and then to shut down itself (the debug adapter).
    /// In addition, the debug adapter must terminate the debuggee if it was started with the
    /// `launch` request. If an `attach` request was used to connect to the debuggee, then the
    /// debug adapter must not terminate the debuggee.
    /// This implicit behavior of when to terminate the debuggee can be overridden with the
    /// `terminateDebuggee` argument (which is only supported by a debug adapter if the
    /// corresponding capability `supportTerminateDebuggee` is true).
    ///
    /// Specification: [Disconnect request](https://microsoft.github.io/debug-adapter-protocol/specification#Requests_Disconnect)
    Disconnect(DisconnectArguments),
    /// Evaluates the given expression in the context of the topmost stack frame.
    /// The expression has access to any variables and arguments that are in scope.
    ///
    /// Specification: [Evaluate arguments](https://microsoft.github.io/debug-adapter-protocol/specification#Requests_Evaluate)
    Evaluate(EvaluateArguments),
    /// The initialize request is sent as the first request from the client to the debug adapter in
    /// order to configure it with client capabilities and to retrieve capabilities from the debug
    /// adapter.
    ///
    /// Until the debug adapter has responded with an initialize response, the client must not send
    /// any additional requests or events to the debug adapter.
    ///
    /// In addition the debug adapter is not allowed to send any requests or events to the client
    /// until  it has responded with an initialize response.
    ///
    /// The initialize request may only be sent once.
    ///
    /// Specification: [InitializeRequest](https://microsoft.github.io/debug-adapter-protocol/specification#Requests_Initialize)
    Initialize(InitializeArguments),
    /// This launch request is sent from the client to the debug adapter to start the debuggee with
    /// or without debugging (if noDebug is true).
    /// Since launching is debugger/runtime specific, the arguments for this request are not part of
    /// this specification.
    ///
    /// Specification: [Launch request](https://microsoft.github.io/debug-adapter-protocol/specification#Requests_Launch)
    Launch(LaunchRequestArguments),
    /// The request executes one step (in the given granularity) for the specified thread and allows
    /// all other threads to run freely by resuming them.
    /// If the debug adapter supports single thread execution (see capability
    /// `supportsSingleThreadExecutionRequests`), setting the `singleThread` argument to true
    /// prevents other suspended threads from resuming.
    /// The debug adapter first sends the response and then a stopped event (with reason step) after
    /// the step has completed.
    ///
    /// Specification: [Next request](https://microsoft.github.io/debug-adapter-protocol/specification#Requests_Next)
    Next(NextArguments),
    /// Restarts a debug session. Clients should only call this request if the corresponding
    /// capability supportsRestartRequest is true.
    /// If the capability is missing or has the value false, a typical client emulates restart by
    /// terminating the debug adapter first and then launching it anew.
    ///
    /// `arguments` is wrapped in `Option` because clients vary in how they encode the absence of
    /// extra restart data: VS Code omits the field, Zed sends `"arguments": null`, and the spec
    /// allows both. Serde's adjacently-tagged enum needs the `Option` to accept `null` here.
    ///
    /// Specification: [Restart request](https://microsoft.github.io/debug-adapter-protocol/specification#Requests_Restart)
    Restart(Option<RestartArguments>),
    /// The request returns the variable scopes for a given stackframe ID.
    ///
    /// Specification: [Scopes request](https://microsoft.github.io/debug-adapter-protocol/specification#Requests_Scopes)
    Scopes(ScopesArguments),
    /// Sets multiple breakpoints for a single source and clears all previous breakpoints in that
    /// source.
    ///
    /// To clear all breakpoint for a source, specify an empty array.
    ///
    /// When a breakpoint is hit, a stopped event (with reason breakpoint) is generated.
    ///
    /// Specification: [SetBreakpointsRequest](https://microsoft.github.io/debug-adapter-protocol/specification#Requests_SetBreakpoints)
    SetBreakpoints(SetBreakpointsArguments),
    /// Replaces all existing function breakpoints with new function breakpoints.
    /// To clear all function breakpoints, specify an empty array.
    /// When a function breakpoint is hit, a stopped event (with reason function breakpoint) is
    /// generated.
    /// Clients should only call this request if the corresponding capability
    /// supportsFunctionBreakpoints is true.
    ///
    /// Specification: [SetFunctionBreakpointsArguments](https://microsoft.github.io/debug-adapter-protocol/specification#Requests_SetFunctionBreakpoints)
    SetFunctionBreakpoints(SetFunctionBreakpointsArguments),
    /// The request returns a stacktrace from the current execution state of a given thread.
    /// A client can request all stack frames by omitting the startFrame and levels arguments. For
    /// performance-conscious clients and if the corresponding capability
    /// `supportsDelayedStackTraceLoading` is true, stack frames can be retrieved in a piecemeal way
    /// with the startFrame and levels arguments. The response of the stackTrace request may
    /// contain a totalFrames property that hints at the total number of frames in the stack. If a
    /// client needs this total number upfront, it can issue a request for a single (first) frame
    /// and depending on the value of totalFrames decide how to proceed. In any case a client should
    /// be prepared to receive fewer frames than requested, which is an indication that the end of
    /// the stack has been reached.
    ///
    /// Specification: [StackTrace request](https://microsoft.github.io/debug-adapter-protocol/specification#Requests_StackTrace)
    StackTrace(StackTraceArguments),
    /// The request resumes the given thread to step into a function/method and allows all other
    /// threads to run freely by resuming them.
    /// If the debug adapter supports single thread execution (see capability
    /// `supportsSingleThreadExecutionRequests`), setting the `singleThread` argument to true
    /// prevents other suspended threads from resuming.
    ///
    /// Specification: [StepIn request](https://microsoft.github.io/debug-adapter-protocol/specification#Requests_StepIn)
    StepIn(StepInArguments),
    /// The request resumes the given thread to step out (return) from a function/method and allows
    /// all other threads to run freely by resuming them.
    /// If the debug adapter supports single thread execution (see capability
    /// `supportsSingleThreadExecutionRequests`), setting the singleThread argument to true prevents
    /// other suspended threads from resuming.
    /// The debug adapter first sends the response and then a stopped event (with reason step) after
    /// the step has completed.
    ///
    /// Specification: [StepOut request](https://microsoft.github.io/debug-adapter-protocol/specification#Requests_StepOut)
    StepOut(StepOutArguments),
    /// The request retrieves a list of all threads.
    ///
    /// Specification: [Threads request](https://microsoft.github.io/debug-adapter-protocol/specification#Requests_Threads)
    Threads,
    /// Retrieves all child variables for the given variable reference.
    /// A filter can be used to limit the fetched children to either named or indexed children.
    ///
    /// Specification: [Variables request](https://microsoft.github.io/debug-adapter-protocol/specification#Requests_Variables)
    Variables(VariablesArguments),
    /// A request the Miden adapter does not implement.
    #[serde(untagged)]
    Unsupported {
        command: String,
        arguments: Option<Value>,
    },
}

/// Represents a request from a client.
///
/// Note that unlike the specification, this implementation does not define a ProtocolMessage base
/// interface. Instead, the only common part (the sequence number) is repeated in the struct.
///
/// Specification: [Request](https://microsoft.github.io/debug-adapter-protocol/specification#Base_Protocol_Request)
#[cfg_attr(feature = "client", derive(Serialize))]
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Request {
    /// Sequence number for the Request.
    ///
    /// From the [specification](https://microsoft.github.io/debug-adapter-protocol/specification#Base_Protocol_ProtocolMessage):
    ///
    /// Sequence number of the message (also known as message ID). The `seq` for
    /// the first message sent by a client or debug adapter is 1, and for each
    /// subsequent message is 1 greater than the previous message sent by that
    /// actor. `seq` can be used to order requests, responses, and events, and to
    /// associate requests with their corresponding responses. For protocol
    /// messages of type `request` the sequence number can be used to cancel the
    /// request.
    pub seq: i64,
    /// The command to execute.
    ///
    /// This is stringly typed in the specification, but represented as an enum for better
    /// ergonomics in Rust code, along with the arguments when present.
    #[serde(flatten)]
    pub command: Command,
}

impl Request {
    /// Create a successful response for a given request. The sequence number will be copied
    /// from `request`, `message` will be `None` (as its neither cancelled nor an error).
    /// The `body` argument contains the response itself.
    pub fn success(self, body: ResponseBody) -> Response {
        Response {
            request_seq: self.seq,
            success: true,
            message: None,
            body: Some(body), // to love
            error: None,
        }
    }

    /// Create an error response for a given request. The sequence number will be copied
    /// from the request, `message` will be `None` (as its neither cancelled nor an error).
    ///
    /// ## Arguments
    ///
    ///   * `req`: The request this response corresponds to.
    ///   * `body`: The body of the response to attach.
    pub fn error(self, error: &str) -> Response {
        Response {
            request_seq: self.seq,
            success: false,
            message: Some(ResponseMessage::Error(error.to_string())),
            body: None,
            error: None,
        }
    }

    /// Create a cancellation response for the given request. The sequence number will be copied
    /// from the request, message will be [`ResponseMessage::Cancelled`], `success` will be false,
    /// and `body` will be `None`.
    pub fn cancellation(self) -> Response {
        Response {
            request_seq: self.seq,
            success: false,
            message: Some(ResponseMessage::Cancelled),
            body: None,
            error: None,
        }
    }

    /// Create an acknowledgement response. This is a shorthand for responding to requests
    /// where the response does not require a body.
    pub fn ack(self) -> Result<Response, ServerError> {
        let body = match self.command {
            Command::Attach(_) => ResponseBody::Attach,
            Command::ConfigurationDone => ResponseBody::ConfigurationDone,
            Command::Disconnect(_) => ResponseBody::Disconnect,
            Command::Launch(_) => ResponseBody::Launch,
            Command::Next(_) => ResponseBody::Next,
            Command::Restart(_) => ResponseBody::Restart,
            Command::StepIn(_) => ResponseBody::StepIn,
            Command::StepOut(_) => ResponseBody::StepOut,
            _ => return Err(ServerError::ResponseConstructError),
        };
        Ok(self.success(body))
    }
}

#[cfg(test)]
mod tests;
