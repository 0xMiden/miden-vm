// Allow unused assignments - required by miette::Diagnostic derive macro
#![allow(unused_assignments)]

use alloc::sync::Arc;

use miden_core::Felt;
use miden_debug_types::{SourceFile, SourceSpan};
use miden_utils_diagnostics::{Diagnostic, miette};

use crate::{ContextId, ErrorContext};

#[derive(Debug, thiserror::Error, Diagnostic)]
pub enum MemoryError {
    #[error("memory address cannot exceed 2^32 but was {addr}")]
    #[diagnostic()]
    AddressOutOfBounds {
        #[label]
        label: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
        addr: u64,
    },
    #[error(
        "memory address {addr} in context {ctx} was read and written, or written twice, in the same clock cycle {clk}"
    )]
    IllegalMemoryAccess { ctx: ContextId, addr: u32, clk: Felt },
    #[error(
        "memory range start address cannot exceed end address, but was ({start_addr}, {end_addr})"
    )]
    InvalidMemoryRange { start_addr: u64, end_addr: u64 },
    #[error(
        "word memory access at address {addr} in context {ctx} is unaligned at clock cycle {clk}"
    )]
    #[diagnostic(help(
        "ensure that the memory address accessed is aligned to a word boundary (it is a multiple of 4)"
    ))]
    UnalignedWordAccess {
        #[label("tried to access memory address {addr}")]
        label: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
        addr: u32,
        ctx: ContextId,
        clk: Felt,
    },
    // Note: we need this version as well because to handle advice provider calls, which don't
    // have access to the clock.
    #[error("word access at memory address {addr} in context {ctx} is unaligned")]
    UnalignedWordAccessNoClk { addr: u32, ctx: ContextId },
}

impl MemoryError {
    pub fn unaligned_word_access(
        addr: u32,
        ctx: ContextId,
        clk: Felt,
        err_ctx: &impl ErrorContext,
    ) -> Self {
        let (label, source_file) = err_ctx.label_and_source_file();
        MemoryError::UnalignedWordAccess { addr, ctx, clk, label, source_file }
    }

    pub fn address_out_of_bounds(addr: u64, err_ctx: &impl ErrorContext) -> Self {
        let (label, source_file) = err_ctx.label_and_source_file();
        MemoryError::AddressOutOfBounds { label, source_file, addr }
    }
}
