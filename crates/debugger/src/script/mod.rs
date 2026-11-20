//! Script-facing debugger facade.
//!
//! This module intentionally exposes a small, stable object model over the
//! debugger rather than binding directly to the TUI/REPL state internals. Python
//! scripting can wrap these types later without coupling Python users to private
//! Rust implementation details.

mod api;
#[cfg(feature = "python")]
pub mod python;

pub use self::api::{
    ScriptBreakpoint, ScriptDebugger, ScriptExecutionContext, ScriptFrame, ScriptSourceLocation,
    ScriptValue,
};
#[cfg(all(test, feature = "python"))]
pub(crate) use self::api::{invocation_debugger, test_debugger};
#[cfg(feature = "python")]
pub use self::python::PythonScriptSession;
