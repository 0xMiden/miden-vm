/// Semantic errors returned by [`crate::EventContext`] reads.
///
/// These errors describe the handler-facing context contract and intentionally do not expose
/// execution-engine implementation details.
#[derive(Debug, Clone, Eq, PartialEq, thiserror::Error)]
pub enum EventContextError {
    /// A field-element address did not fit in the VM's `u32` address space.
    #[error("memory address must be less than 2^32 but was {address}")]
    AddressOutOfBounds { address: u64 },
    /// A half-open range had its end before its start.
    #[error("range start cannot exceed end, but was ({start}, {end})")]
    InvalidRange { start: u64, end: u64 },
    /// Computing or allocating a slice from `start` and `count` overflowed.
    #[error("range starting at {start} with {count} elements overflows")]
    RangeOverflow { start: u64, count: u64 },
    /// An optional memory read or execution-engine provider touched an uninitialized word.
    #[error("memory at address {address} is uninitialized")]
    UninitializedMemory { address: u32 },
    /// A word read used an address which is not divisible by four.
    #[error("word address {address} is not aligned to four elements")]
    UnalignedWord { address: u32 },
    /// A strict advice-stack read extended beyond the stack.
    #[error("advice-stack range ({start}, {end}) exceeds stack length {len}")]
    AdviceStackOutOfBounds { start: u64, end: u64, len: u64 },
}
