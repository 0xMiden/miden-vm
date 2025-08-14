use core::cmp::Ordering;
use crate::{
    Felt,
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

/// A reduced event identifier that wraps a Felt value for efficient storage and ordering.
/// 
/// This is the canonical form used internally for event identification and handler mapping.
/// It provides efficient ordering and maintains compatibility with both legacy u32 events 
/// and enhanced EventId strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReducedEventID(Felt);

impl ReducedEventID {
    /// Create a new ReducedEventID from a Felt value.
    pub const fn new(felt: Felt) -> Self {
        Self(felt)
    }
    
    /// Create from legacy u32 event ID (backward compatibility).
    pub const fn from_u32(id: u32) -> Self {
        Self(Felt::new(id as u64))
    }
    
    /// Get the underlying Felt value.
    pub const fn as_felt(self) -> Felt {
        self.0
    }
    
    /// Get as u64 for internal use.
    pub const fn as_u64(self) -> u64 {
        self.0.as_int()
    }
}

impl From<u32> for ReducedEventID {
    fn from(id: u32) -> Self {
        Self::from_u32(id)
    }
}

impl From<Felt> for ReducedEventID {
    fn from(felt: Felt) -> Self {
        Self::new(felt)
    }
}

// Use u64 value for ordering in handler maps
impl Ord for ReducedEventID {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.as_int().cmp(&other.0.as_int())
    }
}

impl PartialOrd for ReducedEventID {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl core::fmt::Display for ReducedEventID {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ReducedEventID({})", self.0)
    }
}

// Serialization support for storage and network transmission
impl Serializable for ReducedEventID {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.0.write_into(target);
    }
}

impl Deserializable for ReducedEventID {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let felt = Felt::read_from(source)?;
        Ok(Self::new(felt))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use crate::utils::SliceReader;
    
    #[test]
    fn test_reduced_event_id_creation() {
        let felt = Felt::new(12345);
        let reduced_id = ReducedEventID::new(felt);
        
        assert_eq!(reduced_id.as_felt(), felt);
        assert_eq!(reduced_id.as_u64(), 12345);
    }
    
    #[test]
    fn test_from_u32() {
        let reduced_id = ReducedEventID::from_u32(42);
        assert_eq!(reduced_id.as_u64(), 42);
        
        let reduced_id2: ReducedEventID = 42u32.into();
        assert_eq!(reduced_id, reduced_id2);
    }
    
    #[test]
    fn test_ordering() {
        let id1 = ReducedEventID::from_u32(100);
        let id2 = ReducedEventID::from_u32(200);
        let id3 = ReducedEventID::from_u32(100);
        
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
        
        let id1 = ReducedEventID::new(felt1);
        let id2 = ReducedEventID::new(felt2);
        
        assert!(id1 < id2);
        assert_eq!(
            id1.cmp(&id2),
            felt1.as_int().cmp(&felt2.as_int())
        );
    }
    
    #[test]
    fn test_serialization() {
        let original = ReducedEventID::from_u32(12345);
        
        let mut bytes = Vec::new();
        original.write_into(&mut bytes);
        
        let deserialized = ReducedEventID::read_from(&mut SliceReader::new(&bytes)).unwrap();
        assert_eq!(original, deserialized);
    }
}