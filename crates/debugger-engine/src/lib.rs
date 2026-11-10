//! Portable package decoding, typed variable resolution, and replay serialization.
//!
//! The default `std` feature additionally enables interactive execution, profiling, filesystem
//! access, and command-line parsers. DAP support requires `std`.
#![no_std]

#[cfg_attr(not(feature = "std"), macro_use)]
extern crate alloc;

#[cfg(any(test, feature = "std"))]
#[macro_use]
extern crate std;

pub mod debug;
pub mod exec;
pub mod felt;
pub mod glob;
#[cfg(feature = "std")]
mod linker;
mod package;
pub mod profiling;
mod registry;
mod source_path;
#[cfg(test)]
#[path = "tests/utils.rs"]
mod test_utils;

pub use miden_core::events;
pub use miden_debug_types as debug_types;
pub use miden_processor as processor;

#[cfg(feature = "std")]
pub use self::linker::{LinkLibrary, Linkage};
pub use self::{
    debug::*,
    exec::*,
    felt::{Felt, FromMidenRepr, ToMidenRepr, bytes_to_words, push_wasm_ty_to_operand_stack},
    package::read_package_from_bytes,
    registry::HybridPackageRegistry,
    source_path::normalize_source_path,
};
