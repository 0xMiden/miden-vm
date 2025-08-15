use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{fmt, str::FromStr};

use super::EventID;
use crate::{
    Felt,
    crypto::hash::{Blake3_256, Digest},
    sys_events::SystemEvent,
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

// EVENT NAME
// ================================================================================================

/// A human-readable event identifier using library::event naming.
///
/// Each event is uniquely identified by:
/// - `library`: String chosen by library author (e.g., "crypto_lib")
/// - `event`: String for the specific event (e.g., "sign")
/// - "system" is reserved for VM system events
///
/// The machine-usable EventID is derived from Blake3 hash of "library::event"
/// for deterministic, collision-resistant generation. Note that collision
/// resistance is limited due to 64-bit reduction from the full Blake3 hash.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct EventName {
    library: String,
    event: String,
}

impl EventName {
    /// Create a new event name with library and event names.
    /// Takes String parameters to avoid clones.
    pub fn new(
        library: impl Into<String>,
        event: impl Into<String>,
    ) -> Result<Self, EventNameError> {
        let library = library.into();
        let event = event.into();
        if library.is_empty() {
            return Err(EventNameError("library name cannot be empty"));
        }
        if event.is_empty() {
            return Err(EventNameError("event name cannot be empty"));
        }

        // Validate library name: only lowercase letters and underscores
        if !library.chars().all(|c| c.is_ascii_lowercase() || c == '_') {
            return Err(EventNameError(
                "library name must contain only lowercase letters (a-z) and underscores",
            ));
        }

        // Validate event name: only lowercase letters and underscores
        if !event.chars().all(|c| c.is_ascii_lowercase() || c == '_') {
            return Err(EventNameError(
                "event name must contain only lowercase letters (a-z) and underscores",
            ));
        }

        Ok(Self { library, event })
    }

    /// Create a system event (uses reserved "system" library name).
    pub fn system(event: impl Into<String>) -> Self {
        Self {
            library: "system".into(),
            event: event.into(),
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

    /// Returns the machine-usable EventID using Blake3 hash of "library::event".
    pub fn id(&self) -> EventID {
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

        EventID::new(Felt::new(value))
    }
}

// CONVERSION TRAITS
// ================================================================================================

impl From<&EventName> for EventID {
    fn from(event_name: &EventName) -> Self {
        event_name.id()
    }
}

impl From<EventName> for EventID {
    fn from(event_name: EventName) -> Self {
        event_name.id()
    }
}

impl From<SystemEvent> for EventName {
    fn from(sys_event: SystemEvent) -> Self {
        EventName::system(sys_event.to_string())
    }
}

impl fmt::Display for EventName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}::{}", self.library, self.event)
    }
}

impl FromStr for EventName {
    type Err = EventNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Parse "library::event" format
        if let Some(double_colon_pos) = s.find("::") {
            let library = s[..double_colon_pos].to_string();
            let event = s[double_colon_pos + 2..].to_string();

            // Use the same validation as new() method
            Self::new(library, event)
        } else {
            Err(EventNameError("invalid format: expected 'library::event'"))
        }
    }
}

// ERROR HANDLING
// ================================================================================================

/// Simple error type for the few cases where EventName operations can fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventNameError(pub &'static str);

impl fmt::Display for EventNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl core::error::Error for EventNameError {}

// SERIALIZATION
// ================================================================================================

impl Serializable for EventName {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // Write library name
        target.write_usize(self.library.len());
        target.write_bytes(self.library.as_bytes());

        // Write event name
        target.write_usize(self.event.len());
        target.write_bytes(self.event.as_bytes());
    }
}

impl Deserializable for EventName {
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
    fn test_event_name_creation() {
        // Test new library::event API
        let system_event = EventName::system("map_value_to_stack");
        let library_event = EventName::new("my_crypto_lib", "sign").unwrap();
        let another_lib = EventName::new("dex_lib", "swap").unwrap();

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
    fn test_id_generation() {
        let system_event = EventName::system("test_event");
        let lib_event = EventName::new("lib_a", "event_one").unwrap();
        let another_lib = EventName::new("lib_b", "event_one").unwrap();

        let id1 = system_event.id();
        let id2 = lib_event.id();
        let id3 = another_lib.id();

        // Should be deterministic
        assert_eq!(system_event.id(), id1);
        assert_eq!(lib_event.id(), id2);
        assert_eq!(another_lib.id(), id3);

        // Different events should have different IDs
        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        assert_ne!(id1, id3);

        // Blake3 hash should be non-zero
        assert_ne!(id1.as_u64(), 0);
        assert_ne!(id2.as_u64(), 0);
        assert_ne!(id3.as_u64(), 0);
    }

    #[test]
    fn test_no_namespace_collisions() {
        // This was the main problem with the old design - now solved with library names
        let lib1_event = EventName::new("crypto_lib", "sign").unwrap();
        let lib2_event = EventName::new("different_lib", "sign").unwrap();

        // Different libraries with same event name should have different IDs
        assert_ne!(lib1_event.id(), lib2_event.id());

        // But same library + event should be identical
        let duplicate = EventName::new("crypto_lib", "sign").unwrap();
        assert_eq!(lib1_event.id(), duplicate.id());
    }

    #[test]
    fn test_parsing() {
        // Test parsing "library::event" format
        let parsed: EventName = "my_crypto_lib::sign".parse().unwrap();
        let expected = EventName::new("my_crypto_lib", "sign").unwrap();
        assert_eq!(parsed, expected);

        // Test system events
        let system_parsed: EventName = "system::map_value".parse().unwrap();
        let system_expected = EventName::system("map_value");
        assert_eq!(system_parsed, system_expected);

        // Test error cases
        assert!("invalid".parse::<EventName>().is_err());
        assert!("::no_library".parse::<EventName>().is_err());
        assert!("library::".parse::<EventName>().is_err());
    }

    #[test]
    fn test_system_event_validation() {
        let system_event = EventName::system("test");
        assert!(system_event.is_system());

        let library_event = EventName::new("my_lib", "event").unwrap();
        assert!(!library_event.is_system());
    }

    #[test]
    fn test_validation() {
        // Empty library should error
        assert!(EventName::new("", "event").is_err());

        // Empty event should error
        assert!(EventName::new("library", "").is_err());
    }

    #[test]
    fn test_legacy_format_no_special_handling() {
        // Legacy "source/namespace::event_name" format is parsed as regular library::event
        // but no longer gets special translation (e.g., miden_vm -> system)
        let parsed: EventName = "miden_vm_memory::map_value".parse().unwrap();
        assert_eq!(parsed.library(), "miden_vm_memory"); // No translation to "system"
        assert_eq!(parsed.event(), "map_value");

        let parsed: EventName = "miden_stdlib_crypto::hash".parse().unwrap();
        assert_eq!(parsed.library(), "miden_stdlib_crypto"); // No translation to "system"
        assert_eq!(parsed.event(), "hash");
    }
}
