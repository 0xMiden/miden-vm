use alloc::{format, string::{String, ToString}};
use core::{fmt, str::FromStr};
use crate::{
    crypto::hash::{Blake3_256, Digest},
    Felt, 
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable}
};
use super::ReducedEventID;


// EVENT ID
// ================================================================================================

/// A simple, secure event identifier using library::event naming.
/// 
/// Each event is uniquely identified by:
/// - `library`: String chosen by library author (e.g., "my-crypto-lib")  
/// - `event`: String for the specific event (e.g., "SIGN")
/// - "system" is reserved for VM system events
/// 
/// The reduced ID is derived from Blake3 hash of "library::event" for security.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct EventId {
    library: String,
    event: String,
}

impl EventId {
    /// Create a new event ID with library and event names.
    /// Takes String parameters to avoid clones.
    pub fn new(library: String, event: String) -> Result<Self, EventIdError> {
        if library.is_empty() {
            return Err(EventIdError("library name cannot be empty"));
        }
        if event.is_empty() {
            return Err(EventIdError("event name cannot be empty"));  
        }
        
        Ok(Self { library, event })
    }
    
    /// Create a system event (uses reserved "system" library name).
    pub fn system(event: String) -> Self {
        Self {
            library: "system".to_string(),
            event,
        }
    }
    
    /// Get the library name.
    pub fn library(&self) -> &str {
        &self.library
    }
    
    /// Get the event name.  
    pub fn event(&self) -> &str {
        &self.event
    }
    
    /// Check if this is a system event.
    pub fn is_system(&self) -> bool {
        self.library == "system"
    }
    
    /// Constructor accepting &str for convenience (clones strings internally).
    pub fn from_strings(library: &str, event: &str) -> Result<Self, EventIdError> {
        Self::new(library.to_string(), event.to_string())
    }


    /// Returns the reduced form using Blake3 hash of "library::event".
    pub fn reduced_id(&self) -> ReducedEventID {
        let canonical = format!("{}", self);
        let hash = Blake3_256::hash(canonical.as_bytes());
        
        // Take first 8 bytes as little-endian u64
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&hash.as_bytes()[0..8]);
        let value = u64::from_le_bytes(bytes);
        
        ReducedEventID::new(Felt::new(value))
    }
}

// CONVERSION TRAITS
// ================================================================================================

impl From<&EventId> for ReducedEventID {
    fn from(event_id: &EventId) -> Self {
        event_id.reduced_id()
    }
}

impl From<EventId> for ReducedEventID {
    fn from(event_id: EventId) -> Self {
        event_id.reduced_id()
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}::{}", self.library, self.event)
    }
}

impl FromStr for EventId {
    type Err = EventIdError;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Parse "library::event" format
        if let Some(double_colon_pos) = s.find("::") {
            let library = s[..double_colon_pos].to_string();
            let event = s[double_colon_pos + 2..].to_string();
            
            if library.is_empty() {
                return Err(EventIdError("library name cannot be empty"));
            }
            if event.is_empty() {
                return Err(EventIdError("event name cannot be empty"));
            }
            
            Ok(Self { library, event })
        } else {
            Err(EventIdError("invalid format: expected 'library::event'"))
        }
    }
}

// ERROR HANDLING
// ================================================================================================

/// Simple error type for the few cases where EventId operations can fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventIdError(pub &'static str);

impl fmt::Display for EventIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl core::error::Error for EventIdError {}

// SERIALIZATION
// ================================================================================================

impl Serializable for EventId {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // Write library name
        target.write_usize(self.library.len());
        target.write_bytes(self.library.as_bytes());
        
        // Write event name  
        target.write_usize(self.event.len());
        target.write_bytes(self.event.as_bytes());
    }
}

impl Deserializable for EventId {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        // Read library name
        let library_len = source.read_usize()?;
        let library_bytes = source.read_vec(library_len)?;
        let library = String::from_utf8(library_bytes)
            .map_err(|_| DeserializationError::InvalidValue("invalid library string".to_string()))?;
        
        // Read event name
        let event_len = source.read_usize()?;
        let event_bytes = source.read_vec(event_len)?;
        let event = String::from_utf8(event_bytes)
            .map_err(|_| DeserializationError::InvalidValue("invalid event string".to_string()))?;
        
        Ok(Self { library, event })
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_id_creation() {
        // Test new library::event API
        let system_event = EventId::system("MAP_VALUE_TO_STACK".to_string());
        let library_event = EventId::new("my-crypto-lib".to_string(), "SIGN".to_string()).unwrap();
        let another_lib = EventId::new("dex-lib".to_string(), "SWAP".to_string()).unwrap();
        
        // Test Display format
        assert_eq!(format!("{}", system_event), "system::MAP_VALUE_TO_STACK");
        assert_eq!(format!("{}", library_event), "my-crypto-lib::SIGN");
        assert_eq!(format!("{}", another_lib), "dex-lib::SWAP");
        
        // Test accessors
        assert_eq!(system_event.library(), "system");
        assert_eq!(system_event.event(), "MAP_VALUE_TO_STACK");
        assert_eq!(library_event.library(), "my-crypto-lib");
        assert_eq!(library_event.event(), "SIGN");
    }
    
    #[test]
    fn test_reduced_id_generation() {
        let system_event = EventId::system("TEST_EVENT".to_string());
        let lib_event = EventId::new("lib1".to_string(), "EVENT1".to_string()).unwrap();
        let another_lib = EventId::new("lib2".to_string(), "EVENT1".to_string()).unwrap();
        
        let reduced1 = system_event.reduced_id();
        let reduced2 = lib_event.reduced_id();
        let reduced3 = another_lib.reduced_id();
        
        // Should be deterministic
        assert_eq!(system_event.reduced_id(), reduced1);
        assert_eq!(lib_event.reduced_id(), reduced2);
        assert_eq!(another_lib.reduced_id(), reduced3);
        
        // Different events should have different reduced IDs
        assert_ne!(reduced1, reduced2);
        assert_ne!(reduced2, reduced3);
        assert_ne!(reduced1, reduced3);
        
        // Blake3 hash should be non-zero
        assert_ne!(reduced1.as_u64(), 0);
        assert_ne!(reduced2.as_u64(), 0);
        assert_ne!(reduced3.as_u64(), 0);
    }
    
    #[test]
    fn test_no_namespace_collisions() {
        // This was the main problem with the old design - now solved with library names
        let lib1_event = EventId::new("crypto-lib".to_string(), "SIGN".to_string()).unwrap();
        let lib2_event = EventId::new("different-lib".to_string(), "SIGN".to_string()).unwrap();
        
        // Different libraries with same event name should have different reduced IDs
        assert_ne!(lib1_event.reduced_id(), lib2_event.reduced_id());
        
        // But same library + event should be identical
        let duplicate = EventId::new("crypto-lib".to_string(), "SIGN".to_string()).unwrap();
        assert_eq!(lib1_event.reduced_id(), duplicate.reduced_id());
    }
    
    #[test]
    fn test_parsing() {
        // Test parsing "library::event" format
        let parsed: EventId = "my-crypto-lib::SIGN".parse().unwrap();
        let expected = EventId::new("my-crypto-lib".to_string(), "SIGN".to_string()).unwrap();
        assert_eq!(parsed, expected);
        
        // Test system events
        let system_parsed: EventId = "system::MAP_VALUE".parse().unwrap();
        let system_expected = EventId::system("MAP_VALUE".to_string());
        assert_eq!(system_parsed, system_expected);
        
        // Test error cases
        assert!("invalid".parse::<EventId>().is_err());
        assert!("::no-library".parse::<EventId>().is_err());
        assert!("library::".parse::<EventId>().is_err());
    }
    
    #[test]
    fn test_system_event_validation() {
        let system_event = EventId::system("TEST".to_string());
        assert!(system_event.is_system());
        
        let library_event = EventId::new("my-lib".to_string(), "EVENT".to_string()).unwrap();
        assert!(!library_event.is_system());
    }
    
    #[test]  
    fn test_validation() {
        // Empty library should error
        assert!(EventId::new("".to_string(), "EVENT".to_string()).is_err());
        
        // Empty event should error
        assert!(EventId::new("library".to_string(), "".to_string()).is_err());
    }

    #[test]
    fn test_legacy_format_no_special_handling() {
        // Legacy "source/namespace::EVENT_NAME" format is parsed as regular library::event
        // but no longer gets special translation (e.g., miden-vm -> system)
        let parsed: EventId = "miden-vm/memory::MAP_VALUE".parse().unwrap();
        assert_eq!(parsed.library(), "miden-vm/memory"); // No translation to "system"
        assert_eq!(parsed.event(), "MAP_VALUE");
        
        let parsed: EventId = "miden-stdlib/crypto::HASH".parse().unwrap();
        assert_eq!(parsed.library(), "miden-stdlib/crypto"); // No translation to "system"
        assert_eq!(parsed.event(), "HASH");
    }
}