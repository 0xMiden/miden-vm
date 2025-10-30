use crate::EventId;

/// Version of the precompile ID encoding.
///
/// Encoding: (version << 32) | variant_discriminant
const PRECOMPILE_ID_VERSION: u64 = 1;

/// Fixed set of precompiles supported by this VM version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SupportedPrecompile {
    /// Keccak256 hash over memory (stdlib::hash::keccak256::hash_memory)
    KeccakHashMemory = 0,
}

impl SupportedPrecompile {
    /// Returns the canonical `EventId` for this precompile.
    ///
    /// For compatibility with existing programs and tests, this maps to the
    /// well-known event name identifiers.
    pub fn to_event_id(self) -> EventId {
        match self {
            SupportedPrecompile::KeccakHashMemory => {
                EventId::from_name("stdlib::hash::keccak256::hash_memory")
            },
        }
    }

    /// Current version used in potential future discriminant encoding.
    pub const fn version() -> u64 { PRECOMPILE_ID_VERSION }
}


