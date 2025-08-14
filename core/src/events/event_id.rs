use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{fmt, str::FromStr};

use super::ReducedEventID;
use crate::{
    Felt,
    crypto::hash::{Blake3_256, Digest},
    sys_events::SystemEvent,
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

// EVENT ID
// ================================================================================================

/// A structured event identifier using library::event naming.
///
/// Each event is uniquely identified by:
/// - `library`: String chosen by library author (e.g., "my-crypto-lib")
/// - `event`: String for the specific event (e.g., "SIGN")
/// - "system" is reserved for VM system events
///
/// The reduced ID is derived from Blake3 hash of "library::event" for deterministic,
/// collision-resistant generation. Note that collision resistance is limited due to
/// 64-bit reduction from the full Blake3 hash.
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
        
        // Validate library name: only lowercase letters and underscores
        if !library.chars().all(|c| c.is_ascii_lowercase() || c == '_') {
            return Err(EventIdError("library name must contain only lowercase letters (a-z) and underscores"));
        }
        
        // Validate event name: only lowercase letters and underscores
        if !event.chars().all(|c| c.is_ascii_lowercase() || c == '_') {
            return Err(EventIdError("event name must contain only lowercase letters (a-z) and underscores"));
        }

        Ok(Self { library, event })
    }

    /// Create a system event (uses reserved "system" library name).
    pub fn system(event: String) -> Self {
        Self { library: "system".to_string(), event }
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


    /// Returns the reduced form using Blake3 hash of "library::event".
    pub fn reduced_id(&self) -> ReducedEventID {
        // Build the canonical "library::event" string bytes directly to avoid allocation
        let mut canonical_bytes = Vec::with_capacity(self.library.len() + 2 + self.event.len());
        canonical_bytes.extend_from_slice(self.library.as_bytes());
        canonical_bytes.extend_from_slice(b"::");
        canonical_bytes.extend_from_slice(self.event.as_bytes());
        
        let hash = Blake3_256::hash(&canonical_bytes);

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

impl From<SystemEvent> for EventId {
    fn from(sys_event: SystemEvent) -> Self {
        EventId::system(sys_event.to_string())
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

            // Use the same validation as new() method
            Self::new(library, event)
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
        let library = String::from_utf8(library_bytes).map_err(|_| {
            DeserializationError::InvalidValue("invalid library string".to_string())
        })?;

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
        let system_event = EventId::system("map_value_to_stack".to_string());
        let library_event = EventId::new("my_crypto_lib".to_string(), "sign".to_string()).unwrap();
        let another_lib = EventId::new("dex_lib".to_string(), "swap".to_string()).unwrap();

        // Test Display format
        assert_eq!(format!("{system_event}"), "system::map_value_to_stack");
        assert_eq!(format!("{library_event}"), "my_crypto_lib::sign");
        assert_eq!(format!("{another_lib}"), "dex_lib::swap");

        // Test accessors
        assert_eq!(system_event.library(), "system");
        assert_eq!(system_event.event(), "map_value_to_stack");
        assert_eq!(library_event.library(), "my_crypto_lib");
        assert_eq!(library_event.event(), "sign");
    }

    #[test]
    fn test_reduced_id_generation() {
        let system_event = EventId::system("test_event".to_string());
        let lib_event = EventId::new("lib_a".to_string(), "event_one".to_string()).unwrap();
        let another_lib = EventId::new("lib_b".to_string(), "event_one".to_string()).unwrap();

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
        let lib1_event = EventId::new("crypto_lib".to_string(), "sign".to_string()).unwrap();
        let lib2_event = EventId::new("different_lib".to_string(), "sign".to_string()).unwrap();

        // Different libraries with same event name should have different reduced IDs
        assert_ne!(lib1_event.reduced_id(), lib2_event.reduced_id());

        // But same library + event should be identical
        let duplicate = EventId::new("crypto_lib".to_string(), "sign".to_string()).unwrap();
        assert_eq!(lib1_event.reduced_id(), duplicate.reduced_id());
    }

    #[test]
    fn test_parsing() {
        // Test parsing "library::event" format
        let parsed: EventId = "my_crypto_lib::sign".parse().unwrap();
        let expected = EventId::new("my_crypto_lib".to_string(), "sign".to_string()).unwrap();
        assert_eq!(parsed, expected);

        // Test system events
        let system_parsed: EventId = "system::map_value".parse().unwrap();
        let system_expected = EventId::system("map_value".to_string());
        assert_eq!(system_parsed, system_expected);

        // Test error cases
        assert!("invalid".parse::<EventId>().is_err());
        assert!("::no_library".parse::<EventId>().is_err());
        assert!("library::".parse::<EventId>().is_err());
    }

    #[test]
    fn test_system_event_validation() {
        let system_event = EventId::system("test".to_string());
        assert!(system_event.is_system());

        let library_event = EventId::new("my_lib".to_string(), "event".to_string()).unwrap();
        assert!(!library_event.is_system());
    }

    #[test]
    fn test_validation() {
        // Empty library should error
        assert!(EventId::new("".to_string(), "event".to_string()).is_err());

        // Empty event should error
        assert!(EventId::new("library".to_string(), "".to_string()).is_err());
    }

    #[test]
    fn test_legacy_format_no_special_handling() {
        // Legacy "source/namespace::event_name" format is parsed as regular library::event
        // but no longer gets special translation (e.g., miden_vm -> system)
        let parsed: EventId = "miden_vm_memory::map_value".parse().unwrap();
        assert_eq!(parsed.library(), "miden_vm_memory"); // No translation to "system"
        assert_eq!(parsed.event(), "map_value");

        let parsed: EventId = "miden_stdlib_crypto::hash".parse().unwrap();
        assert_eq!(parsed.library(), "miden_stdlib_crypto"); // No translation to "system"
        assert_eq!(parsed.event(), "hash");
    }
}
