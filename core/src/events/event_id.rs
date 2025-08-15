use core::cmp::Ordering;

use crate::{
    Felt,
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

/// An event identifier that wraps a Felt value for clear type distinction.
///
/// This is the canonical form used internally for event identification and handler mapping.
/// It provides ordering and maintains compatibility with both legacy u32 events
/// and enhanced EventName strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventID(Felt);

impl EventID {
    /// Create a new EventID from a Felt value.
    pub const fn new(felt: Felt) -> Self {
        Self(felt)
    }

    /// Create from legacy u32 event ID (backward compatibility).
    pub const fn from_u32(id: u32) -> Self {
        Self(Felt::new(id as u64))
    }

    /// Get the underlying Felt value.
    pub const fn as_felt(&self) -> Felt {
        self.0
    }
}

impl From<u32> for EventID {
    fn from(id: u32) -> Self {
        Self::from_u32(id)
    }
}

impl From<Felt> for EventID {
    fn from(felt: Felt) -> Self {
        Self::new(felt)
    }
}

// Use u64 value for ordering in handler maps
impl Ord for EventID {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.as_int().cmp(&other.0.as_int())
    }
}

impl PartialOrd for EventID {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl core::fmt::Display for EventID {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// Serialization support for storage and network transmission
impl Serializable for EventID {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.0.write_into(target);
    }
}

impl Deserializable for EventID {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let felt = Felt::read_from(source)?;
        Ok(Self::new(felt))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;
    use crate::utils::SliceReader;

    // Test-only methods for EventID
    impl EventID {
        pub fn as_u64(self) -> u64 {
            self.0.as_int()
        }
    }

    #[test]
    fn test_event_id_creation() {
        let felt = Felt::new(12345);
        let event_id = EventID::new(felt);

        assert_eq!(event_id.as_felt(), felt);
        assert_eq!(event_id.as_u64(), 12345);
    }

    #[test]
    fn test_from_u32() {
        let event_id = EventID::from_u32(42);
        assert_eq!(event_id.as_u64(), 42);

        let event_id2: EventID = 42u32.into();
        assert_eq!(event_id, event_id2);
    }

    #[test]
    fn test_ordering() {
        let id1 = EventID::from_u32(100);
        let id2 = EventID::from_u32(200);
        let id3 = EventID::from_u32(100);

        assert!(id1 < id2);
        assert!(id2 > id1);
        assert_eq!(id1, id3);
        assert_eq!(id1.cmp(&id3), Ordering::Equal);
    }

    #[test]
    fn test_felt_ordering() {
        // Test that ordering matches Felt ordering
        let felt1 = Felt::new(0x1000000000000000u64);
        let felt2 = Felt::new(0x2000000000000000u64);

        let id1 = EventID::new(felt1);
        let id2 = EventID::new(felt2);

        assert!(id1 < id2);
        assert_eq!(id1.cmp(&id2), felt1.as_int().cmp(&felt2.as_int()));
    }

    #[test]
    fn test_serialization() {
        let original = EventID::from_u32(12345);

        let mut bytes = Vec::new();
        original.write_into(&mut bytes);

        let deserialized = EventID::read_from(&mut SliceReader::new(&bytes)).unwrap();
        assert_eq!(original, deserialized);
    }
}
