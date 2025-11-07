
use crate::ContextId;

#[derive(Debug, thiserror::Error)]
pub enum MemoryError {
    #[error("memory address cannot exceed 2^32 but was {addr}")]
    AddressOutOfBounds { addr: u64 },
    #[error(
        "memory address {addr} in context {ctx} was accessed multiple times in the same cycle"
    )]
    IllegalMemoryAccess { ctx: ContextId, addr: u32 },
    #[error(
        "memory range start address cannot exceed end address, but was ({start_addr}, {end_addr})"
    )]
    InvalidMemoryRange { start_addr: u64, end_addr: u64 },
    #[error("word memory access at address {addr} in context {ctx} is unaligned")]
    // NOTE: Diagnostic help "ensure that the memory address accessed is aligned to a word boundary
    // (it is a multiple of 4)" will be restored when implementing OperationDiagnostic trait (deferred).
    UnalignedWordAccess { addr: u32, ctx: ContextId },
}
