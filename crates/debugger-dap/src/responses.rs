#[cfg(feature = "integration_testing")]
use fake::Dummy;
#[cfg(feature = "client")]
use serde::Deserialize;
use serde::Serialize;

use crate::types::{
    Breakpoint, Capabilities, Message, Scope, StackFrame, Thread, Variable,
    VariablePresentationHint,
};

/// Represents a response message that is either a cancellation or a short error string.
#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "client", derive(Deserialize))]
#[cfg_attr(feature = "integration_testing", derive(Dummy))]
pub enum ResponseMessage {
    /// Should be sent when the request was canceled
    Cancelled,
    /// The request may be retried once the adapter is in a 'stopped' state.
    NotStopped,
    /// Contains the raw error in short form if [`Response::success`](Response::success) is false.
    /// This raw error might be interpreted by the client and is not shown in the UI.
    #[serde(untagged)]
    Error(String),
}

#[derive(Serialize, Debug, Default, Clone)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "client", derive(Deserialize))]
#[cfg_attr(feature = "integration_testing", derive(Dummy))]
pub struct ContinueResponse {
    /// The value true (or a missing property) signals to the client that all
    /// threads have been resumed. The value false indicates that not all threads
    /// were resumed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub all_threads_continued: Option<bool>,
}

#[derive(Serialize, Debug, Default, Clone)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "client", derive(Deserialize))]
#[cfg_attr(feature = "integration_testing", derive(Dummy))]
pub struct EvaluateResponse {
    /// The result of the evaluate request.
    pub result: String,
    /// The type of the evaluate result.
    /// This attribute should only be returned by a debug adapter if the
    /// corresponding capability `supportsVariableType` is true.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub type_field: Option<String>,
    /// Properties of an evaluate result that can be used to determine how to
    /// render the result in the UI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presentation_hint: Option<VariablePresentationHint>,
    /// If `variablesReference` is > 0, the evaluate result is structured and its
    /// children can be retrieved by passing `variablesReference` to the
    /// `variables` request.
    /// The value should be less than or equal to 2147483647 (2^31-1).
    /// See [Lifetime of Object References](https://microsoft.github.io/debug-adapter-protocol/overview#lifetime-of-objects-references)
    /// in the Overview section of the specification for details.
    pub variables_reference: i64,
    /// The i64 of named child variables.
    /// The client can use this information to present the variables in a paged
    /// UI and fetch them in chunks.
    /// The value should be less than or equal to 2147483647 (2^31-1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub named_variables: Option<i64>,
    /// The i64 of indexed child variables.
    /// The client can use this information to present the variables in a paged
    /// UI and fetch them in chunks.
    /// The value should be less than or equal to 2147483647 (2^31-1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub indexed_variables: Option<i64>,
    /// A memory reference to a location appropriate for this result.
    /// For pointer type eval results, this is generally a reference to the
    /// memory address contained in the pointer.
    /// This attribute should be returned by a debug adapter if corresponding
    /// capability `supportsMemoryReferences` is true.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_reference: Option<String>,
}

#[derive(Serialize, Debug, Default, Clone)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "client", derive(Deserialize))]
#[cfg_attr(feature = "integration_testing", derive(Dummy))]
pub struct ScopesResponse {
    /// The scopes of the stackframe. If the array has length zero, there are no
    /// scopes available.
    pub scopes: Vec<Scope>,
}

#[derive(Serialize, Debug, Default, Clone)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "client", derive(Deserialize))]
#[cfg_attr(feature = "integration_testing", derive(Dummy))]
pub struct SetBreakpointsResponse {
    /// Information about the breakpoints.
    /// The array elements are in the same order as the elements of the
    /// `breakpoints` (or the deprecated `lines`) array in the arguments.
    pub breakpoints: Vec<Breakpoint>,
}

#[derive(Serialize, Debug, Default, Clone)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "client", derive(Deserialize))]
#[cfg_attr(feature = "integration_testing", derive(Dummy))]
pub struct SetFunctionBreakpointsResponse {
    /// Information about the breakpoints. The array elements correspond to the
    /// elements of the `breakpoints` array.
    pub breakpoints: Vec<Breakpoint>,
}

#[derive(Serialize, Debug, Default, Clone)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "client", derive(Deserialize))]
#[cfg_attr(feature = "integration_testing", derive(Dummy))]
pub struct StackTraceResponse {
    /// The frames of the stackframe. If the array has length zero, there are no
    /// stackframes available.
    /// This means that there is no location information available.
    pub stack_frames: Vec<StackFrame>,
    /// The total i64 of frames available in the stack. If omitted or if
    /// `totalFrames` is larger than the available frames, a client is expected
    /// to request frames until a request returns less frames than requested
    /// (which indicates the end of the stack). Returning monotonically
    /// increasing `totalFrames` values for subsequent requests can be used to
    /// enforce paging in the client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_frames: Option<i64>,
}

#[derive(Serialize, Debug, Default, Clone)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "client", derive(Deserialize))]
#[cfg_attr(feature = "integration_testing", derive(Dummy))]
pub struct ThreadsResponse {
    /// All threads.
    pub threads: Vec<Thread>,
}

#[derive(Serialize, Debug, Default, Clone)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "client", derive(Deserialize))]
#[cfg_attr(feature = "integration_testing", derive(Dummy))]
pub struct VariablesResponse {
    /// All (or a range) of variables for the given variable reference.
    pub variables: Vec<Variable>,
}

#[derive(Serialize, Debug, Clone)]
#[serde(tag = "command", content = "body", rename_all = "camelCase")]
#[cfg_attr(feature = "client", derive(Deserialize))]
#[cfg_attr(feature = "integration_testing", derive(Dummy))]
pub enum ResponseBody {
    /// Response to attach request. This is just an acknowledgement, so no body field is required.
    ///
    /// Specification: [Attach request](https://microsoft.github.io/debug-adapter-protocol/specification#Requests_Attach)
    Attach,
    /// Response to `configurationDone` request. This is just an acknowledgement, so no body field
    /// is required.
    ///
    /// Specification: [ConfigurationDone request](https://microsoft.github.io/debug-adapter-protocol/specification#Requests_ConfigurationDone)
    ConfigurationDone,
    /// Response to `continue` request.
    ///
    /// Specification: [Continue request](https://microsoft.github.io/debug-adapter-protocol/specification#Requests_Continue)
    Continue(ContinueResponse),
    /// Response to disconnect request. This is just an acknowledgement, so no body field is
    /// required.
    ///
    /// Specification: [Disconnect request](https://microsoft.github.io/debug-adapter-protocol/specification#Requests_Disconnect)
    Disconnect,
    /// Response to `evaluate` request.
    ///
    /// Specification: [Evaluate request](https://microsoft.github.io/debug-adapter-protocol/specification#Requests_Evaluate)
    Evaluate(EvaluateResponse),
    /// Response to `initialize` request.
    ///
    /// NOTE: we are straying away from the spec here, as the spec says that the response body is
    /// optional, but we are always returning a body because I could not find a way to express
    /// skipping the optional body with serde (and serializing null will make the schema validation
    /// complain).
    ///
    /// Specification: [Initialize request](https://microsoft.github.io/debug-adapter-protocol/specification#Requests_Initialize)
    Initialize(Capabilities),
    /// Response to launch request. This is just an acknowledgement, so no body field is required.
    ///
    /// Specification: [Launch request](https://microsoft.github.io/debug-adapter-protocol/specification#Requests_Launch)
    Launch,
    /// Response to next request. This is just an acknowledgement, so no body field is required.
    ///
    /// Specification: [Next request](https://microsoft.github.io/debug-adapter-protocol/specification#Requests_Next)
    Next,
    /// Response to `restart` request. This is just an acknowledgement, so no body field is
    /// required.
    ///
    /// Specification: [Restart request](https://microsoft.github.io/debug-adapter-protocol/specification#Requests_Restart)
    Restart,
    /// Response to scopes request.
    ///
    /// Specification: [Scopes request](https://microsoft.github.io/debug-adapter-protocol/specification#Requests_Scopes)
    Scopes(ScopesResponse),
    /// Response to setBreakpoints request.
    /// Returned is information about each breakpoint created by this request.
    /// This includes the actual code location and whether the breakpoint could be verified.
    /// The breakpoints returned are in the same order as the elements of the breakpoints
    /// (or the deprecated lines) array in the arguments.
    ///
    /// Specification: [SetBreakpointsRequest](https://microsoft.github.io/debug-adapter-protocol/specification#Requests_SetBreakpoints)
    SetBreakpoints(SetBreakpointsResponse),
    /// Response to setFunctionBreakpoints request.
    /// Returned is information about each breakpoint created by this request.
    ///
    /// Specification: [SetFunctionBreakpointsArguments](https://microsoft.github.io/debug-adapter-protocol/specification#Requests_SetFunctionBreakpoints)
    SetFunctionBreakpoints(SetFunctionBreakpointsResponse),
    /// Response to stackTrace request.
    ///
    /// Specification: [StackTrace request](https://microsoft.github.io/debug-adapter-protocol/specification#Requests_StackTrace)
    StackTrace(StackTraceResponse),
    /// Response to `stepIn` request. This is just an acknowledgement, so no body field is required.
    ///
    /// Specification: [StepIn request](https://microsoft.github.io/debug-adapter-protocol/specification#Requests_StepIn)
    StepIn,
    /// Response to `stepOut` request. This is just an acknowledgement, so no body field is
    /// required.
    ///
    /// Specification: [StepOut request](https://microsoft.github.io/debug-adapter-protocol/specification#Requests_StepOut)
    StepOut,
    /// Response to threads request.
    ///
    /// Specification: [Threads request](https://microsoft.github.io/debug-adapter-protocol/specification#Requests_Threads)
    Threads(ThreadsResponse),
    /// Response to `variables` request.
    ///
    /// Specification: [Variables request](https://microsoft.github.io/debug-adapter-protocol/specification#Requests_Variables)
    Variables(VariablesResponse),
}

/// Represents response to the client.
///
/// The command field (which is a string) is used as a tag in the ResponseBody enum, so users
/// of this crate will control it by selecting the appropriate enum variant for the body.
///
/// There is also no separate `ErrorResponse` struct. Instead, `Error` is just a variant of the
/// ResponseBody enum.
///
/// Specification: [Response](https://microsoft.github.io/debug-adapter-protocol/specification#Base_Protocol_Response)
#[derive(Serialize, Debug, Default, Clone)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "client", derive(Deserialize))]
#[cfg_attr(feature = "integration_testing", derive(Dummy))]
pub struct Response {
    /// Sequence number of the corresponding request.
    #[serde(rename = "request_seq")]
    pub request_seq: i64,
    /// Outcome of the request.
    /// If true, the request was successful and the `body` attribute may contain
    /// the result of the request.
    /// If the value is false, the attribute `message` contains the error in short
    /// form and the `body` may contain additional information (see
    /// `ErrorResponse.body.error`).
    pub success: bool,
    /// Contains the raw error in short form if `success` is false.
    /// This raw error might be interpreted by the client and is not shown in the
    /// UI.
    /// Some predefined values exist.
    /// Values:
    /// 'cancelled': request was cancelled.
    /// etc.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<ResponseMessage>,
    /// Contains request result if success is true and error details if success is
    /// false.
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub body: Option<ResponseBody>,
    /// A structured error message.
    pub error: Option<Message>,
}

#[cfg(test)]
#[path = "responses/tests.rs"]
mod test;
