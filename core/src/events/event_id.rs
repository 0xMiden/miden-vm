use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::{
    fmt,
    str::FromStr,
};

use crate::{
    crypto::hash::{Blake3_256, Digest},
    Felt,
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};
use super::ReducedEventID;

// EVENT SOURCE
// ================================================================================================

/// Hierarchical event source identification system.
/// 
/// This provides a structured way to organize events by their origin, preventing
/// namespace collisions between different libraries and systems.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EventSource {
    /// Built-in VM system events (source_id = 0)
    System,
    
    /// Standard library events (source_id = 1)  
    Stdlib,
    
    /// Third-party library events (source_id = 2+)
    Library(u32),
    
    /// User-defined application events
    User(u32),
}

impl EventSource {
    /// Returns the numeric source ID for backward compatibility.
    pub fn source_id(&self) -> u32 {
        match self {
            EventSource::System => 0,
            EventSource::Stdlib => 1,
            EventSource::Library(id) => *id + 2, // Libraries start from 2
            EventSource::User(id) => *id + 10000, // Users start from 10000 to avoid conflicts
        }
    }

    /// Returns the canonical string prefix for this source.
    pub fn canonical_prefix(&self) -> String {
        match self {
            EventSource::System => "miden-vm".to_string(),
            EventSource::Stdlib => "miden-stdlib".to_string(),
            EventSource::Library(id) => format!("lib-{}", id),
            EventSource::User(id) => format!("user-{}", id),
        }
    }

    /// Creates an EventSource from a canonical prefix string.
    pub fn from_prefix(prefix: &str) -> Result<Self, EventIdError> {
        match prefix {
            "miden-vm" => Ok(EventSource::System),
            "miden-stdlib" => Ok(EventSource::Stdlib),
            _ if prefix.starts_with("lib-") => {
                let id_str = &prefix[4..];
                let id = id_str.parse::<u32>()
                    .map_err(|_| EventIdError::InvalidSourceId(prefix.to_string()))?;
                Ok(EventSource::Library(id))
            },
            _ if prefix.starts_with("user-") => {
                let id_str = &prefix[5..];
                let id = id_str.parse::<u32>()
                    .map_err(|_| EventIdError::InvalidSourceId(prefix.to_string()))?;
                Ok(EventSource::User(id))
            },
            _ => Err(EventIdError::InvalidSourcePrefix(prefix.to_string())),
        }
    }
}

impl fmt::Display for EventSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.canonical_prefix())
    }
}

// EVENT ID
// ================================================================================================

/// A structured, hierarchical event identifier.
/// 
/// EventIds provide a human-readable way to identify events while supporting
/// deterministic hashing to Felt values for VM use. The format is:
/// 
/// `{source}/{namespace}::{name}`
/// 
/// Examples:
/// - `miden-vm/memory::MAP_VALUE_TO_STACK`
/// - `miden-stdlib/crypto::FALCON_SIG_VERIFY`
/// - `user-42/app::CUSTOM_EVENT`
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventId {
    source: EventSource,
    namespace: String,
    name: String,
}

impl EventId {
    /// Creates a new EventId with validation.
    /// 
    /// # Arguments
    /// * `source` - The event source (system, stdlib, library, or user)
    /// * `namespace` - The namespace within the source (e.g., "memory", "crypto")
    /// * `name` - The event name in UPPER_SNAKE_CASE (e.g., "MAP_VALUE_TO_STACK")
    pub fn new(
        source: EventSource,
        namespace: impl Into<String>,
        name: impl Into<String>,
    ) -> Result<Self, EventIdError> {
        let namespace = namespace.into();
        let name = name.into();
        
        Self::validate_namespace(&namespace)?;
        Self::validate_name(&name)?;
        
        Ok(Self {
            source,
            namespace,
            name,
        })
    }

    /// Returns the event source.
    pub fn source(&self) -> &EventSource {
        &self.source
    }

    /// Returns the namespace.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Returns the event name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the canonical string representation.
    /// 
    /// Format: `{source}/{namespace}::{name}`
    pub fn canonical_string(&self) -> String {
        format!("{}/{}::{}", self.source.canonical_prefix(), self.namespace, self.name)
    }

    /// Computes the Blake3 hash of the canonical string.
    /// 
    /// Uses domain separation: `blake3_256("miden/event-id/v1" || canonical_bytes)`
    pub fn hash(&self) -> [u8; 32] {
        const DOMAIN_SEP: &[u8] = b"miden/event-id/v1";
        let canonical = self.canonical_string();
        
        let mut input = Vec::new();
        input.extend_from_slice(DOMAIN_SEP);
        input.extend_from_slice(canonical.as_bytes());
        
        Blake3_256::hash(&input).as_bytes()
    }

    /// Returns the Felt representation of this event ID.
    /// 
    /// The hash is interpreted as little-endian u64 and reduced modulo the base field.
    pub fn felt_id(&self) -> Felt {
        let hash_bytes = self.hash();
        
        // Take first 8 bytes as little-endian u64
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&hash_bytes[0..8]);
        let value = u64::from_le_bytes(bytes);
        
        Felt::new(value)
    }

    /// Returns the reduced form of this EventId for internal storage and handler mapping.
    pub fn reduced_id(&self) -> ReducedEventID {
        ReducedEventID::new(self.felt_id())
    }

    /// Returns the legacy source_id for backward compatibility.
    pub fn source_id(&self) -> u32 {
        self.source.source_id()
    }

    /// Returns a legacy event_id within the source for backward compatibility.
    /// 
    /// This is computed by taking the lower 16 bits of the Felt representation.
    pub fn event_id(&self) -> u16 {
        (self.felt_id().as_int() & 0xFFFF) as u16
    }

    // VALIDATION HELPERS
    // --------------------------------------------------------------------------------------------

    fn validate_namespace(namespace: &str) -> Result<(), EventIdError> {
        if namespace.is_empty() {
            return Err(EventIdError::EmptyNamespace);
        }
        
        // Allow lowercase letters, numbers, underscores, hyphens
        for c in namespace.chars() {
            if !matches!(c, 'a'..='z' | '0'..='9' | '_' | '-') {
                return Err(EventIdError::InvalidNamespaceChar(c));
            }
        }
        
        Ok(())
    }

    fn validate_name(name: &str) -> Result<(), EventIdError> {
        if name.is_empty() {
            return Err(EventIdError::EmptyName);
        }
        
        // Allow uppercase letters, numbers, underscores
        for c in name.chars() {
            if !matches!(c, 'A'..='Z' | '0'..='9' | '_') {
                return Err(EventIdError::InvalidNameChar(c));
            }
        }
        
        Ok(())
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
        write!(f, "{}", self.canonical_string())
    }
}

impl FromStr for EventId {
    type Err = EventIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Expected format: "source/namespace::EVENT_NAME"
        let parts: Vec<&str> = s.split("::").collect();
        if parts.len() != 2 {
            return Err(EventIdError::InvalidFormat(
                "expected format: source/namespace::EVENT_NAME".to_string()
            ));
        }
        
        let name = parts[1].to_string();
        
        // Split source/namespace part
        let source_namespace = parts[0];
        let slash_pos = source_namespace.find('/')
            .ok_or_else(|| EventIdError::InvalidFormat(
                "missing '/' between source and namespace".to_string()
            ))?;
        
        let source_prefix = &source_namespace[..slash_pos];
        let namespace = source_namespace[slash_pos + 1..].to_string();
        
        let source = EventSource::from_prefix(source_prefix)?;
        
        Self::new(source, namespace, name)
    }
}

// EVENT ID ERROR
// ================================================================================================

/// Errors that can occur when working with EventIds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventIdError {
    EmptyNamespace,
    EmptyName,
    InvalidNamespaceChar(char),
    InvalidNameChar(char),
    InvalidFormat(String),
    InvalidSourcePrefix(String),
    InvalidSourceId(String),
}

impl fmt::Display for EventIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EventIdError::EmptyNamespace => write!(f, "namespace cannot be empty"),
            EventIdError::EmptyName => write!(f, "event name cannot be empty"),
            EventIdError::InvalidNamespaceChar(c) => write!(
                f, 
                "invalid character '{}' in namespace (allowed: a-z, 0-9, _, -)", 
                c
            ),
            EventIdError::InvalidNameChar(c) => write!(
                f, 
                "invalid character '{}' in event name (allowed: A-Z, 0-9, _)", 
                c
            ),
            EventIdError::InvalidFormat(msg) => write!(f, "invalid format: {}", msg),
            EventIdError::InvalidSourcePrefix(prefix) => write!(
                f, 
                "invalid source prefix '{}' (expected: miden-vm, miden-stdlib, lib-N, user-N)", 
                prefix
            ),
            EventIdError::InvalidSourceId(id) => write!(f, "invalid source ID: {}", id),
        }
    }
}

impl core::error::Error for EventIdError {}

// SERIALIZATION
// ================================================================================================

impl Serializable for EventId {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // Write event source
        self.source.write_into(target);
        
        // Write namespace as string
        target.write_usize(self.namespace.len());
        target.write_bytes(self.namespace.as_bytes());
        
        // Write name as string
        target.write_usize(self.name.len());
        target.write_bytes(self.name.as_bytes());
    }
}

impl Deserializable for EventId {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let event_source = EventSource::read_from(source)?;
        
        let namespace_len = source.read_usize()?;
        let namespace_bytes = source.read_vec(namespace_len)?;
        let namespace = String::from_utf8(namespace_bytes)
            .map_err(|_| DeserializationError::InvalidValue("invalid namespace string".to_string()))?;
        
        let name_len = source.read_usize()?;
        let name_bytes = source.read_vec(name_len)?;
        let name = String::from_utf8(name_bytes)
            .map_err(|_| DeserializationError::InvalidValue("invalid name string".to_string()))?;
        
        EventId::new(event_source, namespace, name)
            .map_err(|_| DeserializationError::InvalidValue("invalid EventId".to_string()))
    }
}

impl Serializable for EventSource {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            EventSource::System => target.write_u8(0),
            EventSource::Stdlib => target.write_u8(1),
            EventSource::Library(id) => {
                target.write_u8(2);
                target.write_u32(*id);
            }
            EventSource::User(id) => {
                target.write_u8(3);
                target.write_u32(*id);
            }
        }
    }
}

impl Deserializable for EventSource {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let variant = source.read_u8()?;
        match variant {
            0 => Ok(EventSource::System),
            1 => Ok(EventSource::Stdlib),
            2 => {
                let id = source.read_u32()?;
                Ok(EventSource::Library(id))
            }
            3 => {
                let id = source.read_u32()?;
                Ok(EventSource::User(id))
            }
            _ => Err(DeserializationError::InvalidValue("invalid EventSource variant".to_string())),
        }
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_source_creation() {
        assert_eq!(EventSource::System.source_id(), 0);
        assert_eq!(EventSource::Stdlib.source_id(), 1);
        assert_eq!(EventSource::Library(5).source_id(), 7); // 5 + 2
        assert_eq!(EventSource::User(42).source_id(), 10042); // 42 + 10000
    }

    #[test]
    fn test_event_source_canonical_prefix() {
        assert_eq!(EventSource::System.canonical_prefix(), "miden-vm");
        assert_eq!(EventSource::Stdlib.canonical_prefix(), "miden-stdlib");
        assert_eq!(EventSource::Library(123).canonical_prefix(), "lib-123");
        assert_eq!(EventSource::User(456).canonical_prefix(), "user-456");
    }

    #[test]
    fn test_event_source_from_prefix() {
        assert_eq!(EventSource::from_prefix("miden-vm").unwrap(), EventSource::System);
        assert_eq!(EventSource::from_prefix("miden-stdlib").unwrap(), EventSource::Stdlib);
        assert_eq!(EventSource::from_prefix("lib-123").unwrap(), EventSource::Library(123));
        assert_eq!(EventSource::from_prefix("user-456").unwrap(), EventSource::User(456));
        
        assert!(EventSource::from_prefix("invalid").is_err());
        assert!(EventSource::from_prefix("lib-abc").is_err());
    }

    #[test]
    fn test_event_id_creation() {
        let event = EventId::new(EventSource::System, "memory", "MAP_VALUE_TO_STACK").unwrap();
        assert_eq!(event.source(), &EventSource::System);
        assert_eq!(event.namespace(), "memory");
        assert_eq!(event.name(), "MAP_VALUE_TO_STACK");
        assert_eq!(event.canonical_string(), "miden-vm/memory::MAP_VALUE_TO_STACK");
    }

    #[test]
    fn test_event_id_validation() {
        // Valid cases
        assert!(EventId::new(EventSource::System, "memory", "MAP_VALUE").is_ok());
        assert!(EventId::new(EventSource::Stdlib, "crypto-ops", "FALCON_SIG_123").is_ok());
        
        // Invalid cases
        assert!(EventId::new(EventSource::System, "", "NAME").is_err()); // Empty namespace
        assert!(EventId::new(EventSource::System, "memory", "").is_err()); // Empty name
        assert!(EventId::new(EventSource::System, "Memory", "NAME").is_err()); // Uppercase namespace
        assert!(EventId::new(EventSource::System, "memory", "lowercase").is_err()); // Lowercase name
        assert!(EventId::new(EventSource::System, "mem space", "NAME").is_err()); // Space in namespace
        assert!(EventId::new(EventSource::System, "memory", "NAME!").is_err()); // Special char in name
    }

    #[test]
    fn test_event_id_parsing() {
        let parsed: EventId = "miden-vm/memory::MAP_VALUE_TO_STACK".parse().unwrap();
        let expected = EventId::new(EventSource::System, "memory", "MAP_VALUE_TO_STACK").unwrap();
        assert_eq!(parsed, expected);
        
        let parsed2: EventId = "miden-stdlib/crypto::FALCON_SIG_VERIFY".parse().unwrap();
        let expected2 = EventId::new(EventSource::Stdlib, "crypto", "FALCON_SIG_VERIFY").unwrap();
        assert_eq!(parsed2, expected2);
        
        // Invalid parsing
        assert!("invalid".parse::<EventId>().is_err());
        assert!("miden-vm/memory".parse::<EventId>().is_err()); // Missing ::
        assert!("memory::EVENT".parse::<EventId>().is_err()); // Missing source
    }

    #[test]
    fn test_felt_id_generation() {
        let event1 = EventId::new(EventSource::System, "memory", "MAP_VALUE_TO_STACK").unwrap();
        let event2 = EventId::new(EventSource::System, "memory", "MAP_VALUE_TO_STACK_N").unwrap();
        
        let felt1 = event1.felt_id();
        let felt2 = event2.felt_id();
        
        // Should be deterministic
        assert_eq!(event1.felt_id(), felt1);
        
        // Different events should have different IDs
        assert_ne!(felt1, felt2);
        
        // Should generate non-zero values
        assert_ne!(felt1.as_int(), 0);
        assert_ne!(felt2.as_int(), 0);
    }

    #[test]
    fn test_backward_compatibility_ids() {
        let event = EventId::new(EventSource::Library(5), "crypto", "MY_EVENT").unwrap();
        
        // Source ID should match expected calculation
        assert_eq!(event.source_id(), 7); // 5 + 2
        
        // Event ID should be derived from Felt
        let event_id = event.event_id();
        let expected = (event.felt_id().as_int() & 0xFFFF) as u16;
        assert_eq!(event_id, expected);
    }

    #[test]
    fn test_reduced_event_id_conversion() {
        let event = EventId::new(EventSource::User(42), "app", "MY_EVENT").unwrap();
        
        // Test direct method call
        let reduced1 = event.reduced_id();
        assert_eq!(reduced1.as_felt(), event.felt_id());
        
        // Test From trait implementations
        let reduced2: ReducedEventID = (&event).into();
        let reduced3: ReducedEventID = event.clone().into();
        
        assert_eq!(reduced1, reduced2);
        assert_eq!(reduced1, reduced3);
        assert_eq!(reduced2, reduced3);
        
        // Verify the underlying Felt is the same
        assert_eq!(reduced1.as_u64(), event.felt_id().as_int());
    }

    #[test]
    fn test_reduced_event_id_deterministic() {
        let event1 = EventId::new(EventSource::System, "memory", "MAP_VALUE").unwrap();
        let event2 = EventId::new(EventSource::System, "memory", "MAP_VALUE").unwrap();
        
        // Same EventId should produce same ReducedEventID
        assert_eq!(event1.reduced_id(), event2.reduced_id());
        
        // Different EventIds should produce different ReducedEventIDs
        let event3 = EventId::new(EventSource::System, "memory", "UNMAP_VALUE").unwrap();
        assert_ne!(event1.reduced_id(), event3.reduced_id());
    }
}