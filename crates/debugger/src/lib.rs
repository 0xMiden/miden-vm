#![no_std]

#[cfg_attr(not(feature = "std"), macro_use)]
extern crate alloc;

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

#[cfg(feature = "std")]
pub use miden_debug_engine::{HybridPackageRegistry, LinkLibrary};
pub use miden_debug_engine::{debug, debug_types, events, exec, felt, processor};

#[cfg(feature = "std")]
mod config;
#[cfg(feature = "dap")]
mod dap_server;
#[cfg(feature = "flamegraph")]
pub mod flamegraph;
mod input;
#[cfg(feature = "std")]
mod program_loader;

#[cfg(feature = "std")]
pub mod logger;
#[cfg(feature = "std")]
mod ui;

#[cfg(feature = "script")]
mod repl;
#[cfg(feature = "script")]
pub mod script;

#[cfg(feature = "std")]
pub use self::config::{ColorChoice, DebuggerConfig};
#[cfg(feature = "dap")]
pub use self::dap_server::run as run_dap_server;
#[cfg(feature = "script")]
pub use self::repl::run_commands;
#[cfg(feature = "repl")]
pub use self::repl::{run as run_repl, run_with_log_level as run_repl_with_log_level};
#[cfg(feature = "std")]
pub use self::ui::{DebugMode, State};
#[cfg(feature = "tui")]
pub use self::ui::{
    run, run_replay_and_log_level, run_with_log_level, run_with_state, run_with_state_and_log_level,
};
pub use self::{
    debug::*,
    exec::*,
    felt::{
        Felt, FromMidenRepr, RawFelt, ToMidenRepr, bytes_to_words, push_wasm_ty_to_operand_stack,
    },
    input::InputFile,
};
