use miden_core::Felt;

use crate::ContextId;

#[derive(Debug, thiserror::Error)]
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
    #[error(
        "word memory access at address {addr} in context {ctx} is unaligned at clock cycle {clk}"
    )]
    // TODO: restore help "ensure that the memory address accessed is aligned to a word boundary
    // (it is a multiple of 4)"
    UnalignedWordAccess { addr: u32, ctx: ContextId, clk: Felt },
    // Note: we need this version as well because to handle advice provider calls, which don't
    // have access to the clock.
    #[error("word access at memory address {addr} in context {ctx} is unaligned")]
    UnalignedWordAccessNoClk { addr: u32, ctx: ContextId },
}
