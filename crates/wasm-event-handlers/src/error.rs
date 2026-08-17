//! Error types for loading and running Wasm event handler modules.

use alloc::string::String;

use miden_processor::event::EventName;

/// An error raised while loading and validating a Wasm handler module.
#[derive(Debug, thiserror::Error)]
pub enum WasmHandlerLoadError {
    /// The module declares an ABI version this crate does not support.
    #[error("handler module declares ABI version {declared}, but this host supports {supported}")]
    AbiVersionMismatch {
        /// The version the module declares.
        declared: u32,
        /// The version this crate implements.
        supported: u32,
    },

    /// The Wasm binary failed to parse or validate.
    #[error("invalid Wasm module: {0}")]
    InvalidModule(String),

    /// The module imports from a namespace other than `miden:event/v1`.
    #[error(
        "handler module imports '{module}::{name}', but only imports from \
         '{allowed}' are allowed",
        allowed = miden_event_handler_abi::IMPORT_MODULE
    )]
    ForbiddenImport {
        /// The import module namespace.
        module: String,
        /// The import name.
        name: String,
    },

    /// The module has a start section. No guest code may run before fuel and limits are
    /// installed, so start functions are rejected.
    #[error("handler module has a start section; start functions are not allowed")]
    StartSection,

    /// The module could not be instantiated against the host function set. This covers imports
    /// with a wrong signature.
    #[error("handler module failed to instantiate: {0}")]
    Instantiation(String),

    /// A manifest entry names an export the module does not have, or the export does not have
    /// the `() -> ()` signature.
    #[error(
        "manifest export '{export}' is missing or does not have the () -> () signature: {reason}"
    )]
    BadExport {
        /// The export name from the manifest.
        export: String,
        /// The underlying resolution error.
        reason: String,
    },

    /// The manifest contains the same event more than once.
    #[error("event '{event}' appears more than once in the handler manifest")]
    DuplicateEvent {
        /// The duplicated event name.
        event: EventName,
    },

    /// The manifest uses a name in the reserved `sys::` namespace.
    #[error("event '{event}' uses the reserved 'sys::' namespace")]
    ReservedEvent {
        /// The offending event name.
        event: EventName,
    },

    /// The package's `event_handlers` section is malformed.
    #[error("invalid 'event_handlers' package section")]
    Section(#[from] miden_mast_package::EventHandlerSectionError),
}

/// An error raised while a handler runs. Converted into the boxed
/// [`EventError`](miden_processor::event::EventError) the processor expects.
///
/// The processor enriches the error with the event name, the event ID, and the source location
/// of the `emit`, so these messages carry only the handler-local cause.
#[derive(Debug, thiserror::Error)]
pub(crate) enum WasmHandlerRunError {
    /// The guest reported an error through the `fail` host function.
    #[error("{0}")]
    Failed(String),

    /// The handler used up its fuel budget.
    #[error("handler ran out of fuel (limit: {0})")]
    OutOfFuel(u64),

    /// The handler trapped: a Wasm trap, a defect the host functions detected (bad pointer
    /// range, non-canonical field element, mutation over the size limit), or a resource-limit
    /// violation.
    #[error("handler trapped: {0}")]
    Trapped(String),

    /// The module failed to instantiate at call time.
    #[error("failed to instantiate handler module: {0}")]
    Instantiation(String),
}

/// A defect the host functions detected in guest-provided data. Raised as a Wasm trap so the
/// handler stops immediately and its buffered mutations are discarded.
#[derive(Debug)]
pub(crate) struct HostTrap(pub String);

impl core::fmt::Display for HostTrap {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl wasmi::errors::HostError for HostTrap {}
