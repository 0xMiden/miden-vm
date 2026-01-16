// Allow unused assignments - required by miette::Diagnostic derive macro
#![allow(unused_assignments)]

use miden_core::Felt;
use miden_utils_diagnostics::{Diagnostic, miette};

use crate::ContextId;

/// Lightweight error type for memory operations.
///
/// This enum captures error conditions without expensive context information (no
/// source location, no file references). When a `MemoryError` propagates up to
/// become an `ExecutionError`, the context is resolved lazily via
/// `MapExecErr::map_exec_err`.
#[derive(Debug, thiserror::Error, Diagnostic)]
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
    #[error("word access at memory address {addr} in context {ctx} is unaligned")]
    #[diagnostic(help(
        "ensure that the memory address accessed is aligned to a word boundary (it is a multiple of 4)"
    ))]
    UnalignedWordAccess { addr: u32, ctx: ContextId },
}
