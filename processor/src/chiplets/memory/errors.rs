// Allow unused assignments - required by thiserror and Diagnostic derive macros
#![allow(unused_assignments)]

use miden_utils_diagnostics::{Diagnostic, miette};

use crate::ContextId;

#[derive(Debug, thiserror::Error, Diagnostic)]
pub enum MemoryError {
    #[error("memory address {addr} exceeds maximum addressable space")]
    #[diagnostic(help(
        "valid memory addresses must be in range [0, 2^32-1] (4294967295). Check stack values before memory operations"
    ))]
    AddressOutOfBounds { addr: u64 },
    #[error("memory conflict at address {addr} in context {ctx}")]
    #[diagnostic(help(
        "a memory address cannot be both read and written, or written multiple times, in the same clock cycle. This typically indicates a bug in the VM implementation"
    ))]
    IllegalMemoryAccess { ctx: ContextId, addr: u32 },
    #[error("invalid memory range: start {start_addr} exceeds end {end_addr}")]
    #[diagnostic(help("memory range operations require start_addr ≤ end_addr"))]
    InvalidMemoryRange { start_addr: u64, end_addr: u64 },
    #[error("word memory access at address {addr} in context {ctx} is unaligned")]
    #[diagnostic(help(
        "ensure that the memory address accessed is aligned to a word boundary (it is a multiple of 4)"
    ))]
    UnalignedWordAccess { addr: u32, ctx: ContextId },
}
